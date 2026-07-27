export function mount(context = {}) {
  const root = context.root || document.getElementById('routePreview');
  const api = context.api || {};
  const ui = context.ui || {};
  const utils = context.utils || {};
  const escapeHtml = utils.escapeHtml || ((value) => String(value ?? '').replace(/[&<>"']/g, (ch) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[ch])));
  const formatInteger = utils.formatInteger || ((value) => new Intl.NumberFormat('zh-CN').format(Number(value) || 0));
  const fetchApi = api.fetch || (async (name, url) => {
    const response = await fetch(url, { credentials: 'same-origin', cache: 'no-store' });
    const json = await response.json().catch(() => ({}));
    const ok = response.ok && json?.ok !== false;
    return { name, ok, data: json?.data ?? json, raw: json, error: ok ? null : new Error(json?.error?.message || json?.message || response.statusText || 'request failed') };
  });

  const VERSION = '20260720-03';
  const MODULE_CLASS = 'system-settings-route-host';
  const ENDPOINT = '/api/v1/system/basic';
  const SAVE_ENDPOINTS = ['/api/v1/system/settings', '/api/v1/save_system_settings'];
  const SYSTEM_GENERAL_TABS = [
    { id: 'general', label: '常规' },
    { id: 'logs', label: '日志' },
    { id: 'time', label: '时间同步' },
    { id: 'zram', label: 'Zram设置' }
  ];
  const SYSTEM_STARTUP_TABS = [
    { id: 'scripts', label: '启动脚本' },
    { id: 'local', label: '本地启动脚本' }
  ];
  const SYSTEM_FLASH_TABS = [
    { id: 'operations', label: '操作' },
    { id: 'config', label: '配置' }
  ];
  const SYSTEM_ADVANCED_TABS = [
    { id: 'performance', label: '性能与诊断' },
    { id: 'alg', label: 'ALG 设置' },
    { id: 'cpu', label: 'CPU 中断控制' },
    { id: 'kernel', label: '内核设置' }
  ];
  const page = currentSystemPage();

  const state = {
    data: normalizeSystemSettings({}),
    baseline: null,
    tab: tabFromLocation(),
    startupTab: startupTabFromLocation(),
    flashTab: flashTabFromLocation(),
    advancedTab: advancedTabFromLocation(),
    flashPreserveText: '',
    flashPreservePath: '/etc/sysupgrade.conf',
    flashPreserveLoading: false,
    flashPreserveAvailable: false,
    flashBackupFile: null,
    flashFirmwareFile: null,
    signatureUpdateFile: null,
    signatureUpdateStatus: null,
    flashKeepSettings: null,
    flashWorking: '',
    flashConfirm: '',
    flashMessage: '',
    flashError: '',
    operationWorking: '',
    twofaWorking: false,
    pairWorking: false,
    bindingDialog: '',
    pairState: '',
    pairBaselineIds: [],
    pairCandidate: null,
    pairTimer: 0,
    pairPollTicks: 0,
    pairPollBusy: false,
    qrGeneratorLoading: false,
    qrGeneratorError: '',
    deviceWorking: '',
    loading: true,
    error: '',
    saving: false,
    avatarWorking: false,
    saveError: '',
    savedAt: 0,
    timer: 0,
    clockTimer: 0,
    mounted: true,
    seq: 0,
    saveCapable: true,
    touchedFields: new Set()
  };

  function currentSystemPage() {
    const id = context.item?.id || context.id || '';
    const path = context.path || context.item?.path || window.location.hash || window.location.pathname || '';
    const text = String(path);
    if (id === 'system-admin' || /\/system\/admin(?:$|[?#/])/.test(text)) return 'admin';
    if (id === 'system-startup' || /\/system\/startup(?:$|[?#/])/.test(text)) return 'startup';
    if (id === 'system-crontab' || /\/system\/crontab(?:$|[?#/])/.test(text)) return 'crontab';
    if (id === 'system-advanced' || /\/system\/advanced(?:$|[?#/])/.test(text)) return 'advanced';
    if (id === 'storage-mounts' || id === 'system-mounts' || /\/(?:storage|system)\/mounts(?:$|[?#/])/.test(text)) return 'mounts';
    if (id === 'system-flash' || /\/system\/flash(?:$|[?#/])/.test(text)) return 'flash';
    return 'general';
  }

  function tabFromLocation() {
    try {
      const url = new URL(window.location.href);
      const fromSearch = url.searchParams.get('sgtab');
      const fromHash = (window.location.hash.match(/[?&]sgtab=([^&]+)/) || [])[1];
      const value = decodeURIComponent(fromSearch || fromHash || localStorage.getItem('dwrt.system.general.tab') || 'general');
      return SYSTEM_GENERAL_TABS.some((item) => item.id === value) ? value : 'general';
    } catch (_) {
      return 'general';
    }
  }

  function setTab(tab) {
    state.tab = SYSTEM_GENERAL_TABS.some((item) => item.id === tab) ? tab : 'general';
    try { localStorage.setItem('dwrt.system.general.tab', state.tab); } catch (_) {}
  }

  function startupTabFromLocation() {
    try {
      const url = new URL(window.location.href);
      const fromSearch = url.searchParams.get('sstab');
      const fromHash = (window.location.hash.match(/[?&]sstab=([^&]+)/) || [])[1];
      const value = decodeURIComponent(fromSearch || fromHash || localStorage.getItem('dwrt.system.startup.tab') || 'scripts');
      return SYSTEM_STARTUP_TABS.some((item) => item.id === value) ? value : 'scripts';
    } catch (_) {
      return 'scripts';
    }
  }

  function setStartupTab(tab) {
    state.startupTab = SYSTEM_STARTUP_TABS.some((item) => item.id === tab) ? tab : 'scripts';
    try { localStorage.setItem('dwrt.system.startup.tab', state.startupTab); } catch (_) {}
  }

  function flashTabFromLocation() {
    try {
      const url = new URL(window.location.href);
      const fromSearch = url.searchParams.get('sftab');
      const fromHash = (window.location.hash.match(/[?&]sftab=([^&]+)/) || [])[1];
      const value = decodeURIComponent(fromSearch || fromHash || localStorage.getItem('dwrt.system.flash.tab') || 'operations');
      return SYSTEM_FLASH_TABS.some((item) => item.id === value) ? value : 'operations';
    } catch (_) {
      return 'operations';
    }
  }

  function setFlashTab(tab) {
    state.flashTab = SYSTEM_FLASH_TABS.some((item) => item.id === tab) ? tab : 'operations';
    try { localStorage.setItem('dwrt.system.flash.tab', state.flashTab); } catch (_) {}
  }

  function advancedTabFromLocation() {
    try {
      const url = new URL(window.location.href);
      const fromSearch = url.searchParams.get('satab');
      const fromHash = (window.location.hash.match(/[?&]satab=([^&]+)/) || [])[1];
      const value = decodeURIComponent(fromSearch || fromHash || localStorage.getItem('dwrt.system.advanced.tab') || 'performance');
      return SYSTEM_ADVANCED_TABS.some((item) => item.id === value) ? value : 'performance';
    } catch (_) {
      return 'performance';
    }
  }

  function setAdvancedTab(tab) {
    state.advancedTab = SYSTEM_ADVANCED_TABS.some((item) => item.id === tab) ? tab : 'performance';
    try { localStorage.setItem('dwrt.system.advanced.tab', state.advancedTab); } catch (_) {}
  }

  function clone(value) {
    try { return structuredClone(value); } catch (_) { return JSON.parse(JSON.stringify(value || {})); }
  }

  function stableValue(value) {
    if (Array.isArray(value)) return value.map(stableValue);
    if (value && typeof value === 'object') {
      const out = {};
      Object.keys(value).sort().forEach((key) => {
        if (['ts', 'saved_at', 'save_error', 'cache_age_ms', 'source_error', 'stale', 'degraded', 'pairing', 'paired_devices', 'tokens', 'secret', 'otpauth_url', 'qr_svg', 'qr_png', 'qr_svg_supported', 'qr_source', 'qr_format', 'qr_reason', 'issuer', 'account', 'label', 'algorithm', 'already_enabled', 'code', 'disable_code', 'avatar_preview_url', 'avatar_broken_url', 'avatar_upload_error', 'avatar_filename', 'last_action', 'last_reload_at', 'reloaded', 'path', 'backup_path', 'flash'].includes(key)) return;
        if (/_requested_at$/.test(key)) return;
        out[key] = stableValue(value[key]);
      });
      return out;
    }
    return value;
  }

  function markBaseline(source = state.data) {
    state.baseline = stableValue(clone(normalizeSystemSettings(source)));
  }

  function dirty() {
    if (!state.baseline) return false;
    return JSON.stringify(stableValue(clone(state.data))) !== JSON.stringify(state.baseline);
  }

  function valueAtPath(source, path) {
    return String(path || '').split('.').filter(Boolean).reduce((node, key) => {
      if (node === undefined || node === null) return undefined;
      return node[key];
    }, source);
  }

  function setValueAtPath(target, path, value) {
    const parts = String(path || '').split('.').filter(Boolean);
    if (!parts.length) return;
    let node = target;
    while (parts.length > 1) {
      const key = parts.shift();
      const nextKey = parts[0];
      if (!node[key] || typeof node[key] !== 'object') node[key] = /^\d+$/.test(nextKey || '') ? [] : {};
      node = node[key];
    }
    node[parts[0]] = clone(value);
  }

  function applyHydratedSettings(incoming = {}) {
    const drafts = new Map();
    state.touchedFields.forEach((path) => drafts.set(path, clone(valueAtPath(state.data, path))));
    const hydrated = mergeSystemSettingsValue(normalizeSystemSettings({}), incoming || {});
    markBaseline(hydrated);
    drafts.forEach((value, path) => setValueAtPath(hydrated, path, value));
    state.data = normalizeSystemSettings(hydrated);
  }

  function systemLoadingStatus() {
    if (!state.loading) return '';
    return `
      <div class="system-hydration-status" role="status" aria-live="polite">
        ${systemSettingsIcon('sync')}
        <span>正在读取系统设置</span>
      </div>`;
  }

  function mergeSystemSettingsValue(base = {}, incoming = {}) {
    const left = base && typeof base === 'object' ? base : {};
    const right = incoming && typeof incoming === 'object' ? incoming : {};
    return normalizeSystemSettings({
      ...left,
      ...right,
      general: { ...(left.general || {}), ...(right.general || {}) },
      admin: { ...(left.admin || {}), ...(right.admin || {}) },
      admins: Array.isArray(right.admins) ? right.admins : (Array.isArray(left.admins) ? left.admins : []),
      ssh: { ...(left.ssh || {}), ...(right.ssh || {}) },
      api: {
        ...(left.api || {}),
        ...(right.api || {}),
        pairing: { ...((left.api || {}).pairing || {}), ...((right.api || {}).pairing || {}) },
        paired_devices: Array.isArray((right.api || {}).paired_devices) ? (right.api || {}).paired_devices : (Array.isArray((left.api || {}).paired_devices) ? (left.api || {}).paired_devices : []),
        tokens: Array.isArray((right.api || {}).tokens) ? (right.api || {}).tokens : (Array.isArray((left.api || {}).tokens) ? (left.api || {}).tokens : [])
      },
      twofa: { ...(left.twofa || {}), ...(right.twofa || {}) },
      startup: {
        ...(left.startup || {}),
        ...(right.startup || {}),
        services: Array.isArray((right.startup || {}).services) ? (right.startup || {}).services : (Array.isArray((left.startup || {}).services) ? (left.startup || {}).services : [])
      },
      crontab: {
        ...(left.crontab || {}),
        ...(right.crontab || {}),
        jobs: Array.isArray((right.crontab || {}).jobs) ? (right.crontab || {}).jobs : (Array.isArray((left.crontab || {}).jobs) ? (left.crontab || {}).jobs : [])
      },
      mounts: {
        ...(left.mounts || {}),
        ...(right.mounts || {}),
        points: Array.isArray((right.mounts || {}).points) ? (right.mounts || {}).points : (Array.isArray((left.mounts || {}).points) ? (left.mounts || {}).points : [])
      },
      flash: { ...(left.flash || {}), ...(right.flash || {}) },
      advanced: { ...(left.advanced || {}), ...(right.advanced || {}) },
      dreamingwrt: {
        ...(left.dreamingwrt || {}),
        ...(right.dreamingwrt || {}),
        material_glass: { ...((left.dreamingwrt || {}).material_glass || {}), ...((right.dreamingwrt || {}).material_glass || {}) },
        menu_liquid_glass: { ...((left.dreamingwrt || {}).menu_liquid_glass || {}), ...((right.dreamingwrt || {}).menu_liquid_glass || {}) },
        signature_update: { ...((left.dreamingwrt || {}).signature_update || {}), ...((right.dreamingwrt || {}).signature_update || {}) }
      },
      capabilities: { ...(left.capabilities || {}), ...(right.capabilities || {}) }
    });
  }

  function normalizeSystemSettings(source = {}) {
    const data = source && typeof source === 'object' ? source : {};
    const general = data.general && typeof data.general === 'object' ? data.general : {};
    const advanced = data.advanced && typeof data.advanced === 'object' ? data.advanced : {};
    const dreamingwrt = data.dreamingwrt && typeof data.dreamingwrt === 'object' ? data.dreamingwrt : {};
    const adminSource = data.admin && typeof data.admin === 'object' ? data.admin : {};
    const admins = Array.isArray(data.admins) ? data.admins : [];
    const primaryAdmin = admins.find((item) => item && (item.id === 'root' || item.username === adminSource.username)) || admins[0] || {};
    const admin = {
      ...adminSource,
      username: stringOr(adminSource.username || primaryAdmin.username || 'root'),
      role: stringOr(adminSource.role || primaryAdmin.role || '超级管理员'),
      avatar_url: stringOr(adminSource.avatar_url || adminSource.avatar || primaryAdmin.avatar_url || primaryAdmin.avatar),
      avatar_preview_url: stringOr(adminSource.avatar_preview_url),
      web_login_timeout_min: Math.max(1, Math.min(1440, Number(adminSource.web_login_timeout_min || primaryAdmin.web_login_timeout_min || 60))),
      new_password: stringOr(adminSource.new_password),
      confirm_password: stringOr(adminSource.confirm_password)
    };
    const sshSource = data.ssh && typeof data.ssh === 'object' ? data.ssh : {};
    const apiSource = data.api && typeof data.api === 'object' ? data.api : {};
    const pairing = apiSource.pairing && typeof apiSource.pairing === 'object' ? apiSource.pairing : {};
    const twofaSource = data.twofa && typeof data.twofa === 'object' ? data.twofa : {};
    const startupSource = data.startup && typeof data.startup === 'object' ? data.startup : {};
    const crontabSource = data.crontab && typeof data.crontab === 'object' ? data.crontab : {};
    const mountsSource = data.mounts && typeof data.mounts === 'object' ? data.mounts : {};
    const flashSource = data.flash && typeof data.flash === 'object' ? data.flash : {};
    const wallpaperSource = dreamingwrt.wallpaper && typeof dreamingwrt.wallpaper === 'object' ? dreamingwrt.wallpaper : {};
    const dashboardSource = dreamingwrt.dashboard && typeof dreamingwrt.dashboard === 'object' ? dreamingwrt.dashboard : {};
    const signatureUpdateSource = dreamingwrt.signature_update && typeof dreamingwrt.signature_update === 'object' ? dreamingwrt.signature_update : {};
    const materialSource = dreamingwrt.material_glass && typeof dreamingwrt.material_glass === 'object' ? dreamingwrt.material_glass : {};
    const menuGlassSource = dreamingwrt.menu_liquid_glass && typeof dreamingwrt.menu_liquid_glass === 'object' ? dreamingwrt.menu_liquid_glass : {};
    return {
      ...data,
      general: {
        ...general,
        hostname: stringOr(general.hostname),
        model: stringOr(general.model),
        version: stringOr(general.version),
        description: Object.prototype.hasOwnProperty.call(general, 'description') ? general.description : (general.model || ''),
        note: stringOr(general.note),
        timezone: general.timezone || 'Asia/Shanghai',
        time_format: general.time_format || '24h',
        show_timezone_name: general.show_timezone_name !== false,
        time_sync: general.time_sync !== false,
        ntp_server_enabled: Boolean(general.ntp_server_enabled),
        ntp_use_dhcp: general.ntp_use_dhcp !== false,
        ntp_servers: systemNtpServers(general),
        language: general.language || 'auto',
        log_buffer_kb: Number(general.log_buffer_kb || 128),
        log_level: general.log_level || 'warning',
        cron_log_level: general.cron_log_level || 'error',
        remote_log_host: stringOr(general.remote_log_host),
        remote_log_port: Number(general.remote_log_port || 514),
        remote_log_protocol: general.remote_log_protocol || 'udp',
        log_file_path: general.log_file_path || '/tmp/system.log'
      },
      advanced: {
        ...advanced,
        memory_total_mb: Number(advanced.memory_total_mb || 512),
        zram_size_mb: Number(advanced.zram_size_mb || 256),
        zram_algorithm: advanced.zram_algorithm || 'lz4'
      },
      admin,
      admins,
      ssh: {
        ...sshSource,
        enabled: sshSource.enabled !== false,
        port: Number(sshSource.port || 22),
        password_login: sshSource.password_login !== false,
        root_password_login: sshSource.root_password_login !== false,
        key_only: Boolean(sshSource.key_only),
        idle_timeout_min: Number(sshSource.idle_timeout_min ?? 30)
      },
      api: {
        ...apiSource,
        enabled: apiSource.enabled !== false,
        lan_only: apiSource.lan_only !== false,
        pairing_enabled: apiSource.pairing_enabled !== false,
        local_confirm_required: apiSource.local_confirm_required !== false,
        event_stream_enabled: apiSource.event_stream_enabled !== false,
        audit_enabled: apiSource.audit_enabled !== false,
        base_url: apiSource.base_url || '/api/v1',
        token_ttl_min: Number(apiSource.token_ttl_min || 15),
        refresh_token_days: Number(apiSource.refresh_token_days || 30),
        pairing: {
          ...pairing,
          active: Object.prototype.hasOwnProperty.call(pairing, 'active')
            ? Boolean(pairing.active)
            : Boolean(pairing.pair_id || pairing.code),
          pair_id: stringOr(pairing.pair_id || pairing.app_device_id),
          code: stringOr(pairing.code),
          expires_in: Number(pairing.expires_in || 0),
          expires_at: Number(pairing.expires_at || 0),
          requires_local_confirm: pairing.requires_local_confirm !== false
        },
        paired_devices: Array.isArray(apiSource.paired_devices) ? apiSource.paired_devices : (Array.isArray(data.paired_devices) ? data.paired_devices : []),
        tokens: Array.isArray(apiSource.tokens) ? apiSource.tokens : []
      },
      twofa: {
        ...twofaSource,
        username: stringOr(twofaSource.username || admin.username),
        twofa_enabled: Boolean(twofaSource.twofa_enabled || twofaSource.enabled || admin.two_factor),
        bound_at: Number(twofaSource.bound_at || 0),
        method: twofaSource.method || 'totp',
        digits: Number(twofaSource.digits || 6),
        period: Number(twofaSource.period || 30),
        window: Number(twofaSource.window || 1),
        secret: stringOr(twofaSource.secret),
        otpauth_url: stringOr(twofaSource.otpauth_url),
        code: stringOr(twofaSource.code),
        disable_code: stringOr(twofaSource.disable_code)
      },
      startup: {
        ...startupSource,
        services: Array.isArray(startupSource.services) ? startupSource.services : [],
        local_script: stringOr(startupSource.local_script ?? startupSource.rc_local ?? startupSource.content)
      },
      crontab: {
        ...crontabSource,
        jobs: Array.isArray(crontabSource.jobs) ? crontabSource.jobs : [],
        text: typeof crontabSource.text === 'string' ? crontabSource.text : ''
      },
      mounts: {
        ...mountsSource,
        points: Array.isArray(mountsSource.points) ? mountsSource.points : [],
        auto_mount: mountsSource.auto_mount !== false,
        auto_swap: Boolean(mountsSource.auto_swap),
        check_fs: Boolean(mountsSource.check_fs)
      },
      flash: {
        ...flashSource,
        current_firmware: stringOr(flashSource.current_firmware || general.version || 'Dreaming OS'),
        build_time: stringOr(flashSource.build_time),
        kernel: stringOr(flashSource.kernel),
        keep_settings: flashSource.keep_settings !== false,
        last_backup_at: Number(flashSource.last_backup_at || 0),
        backup_size: stringOr(flashSource.backup_size)
      },
      dreamingwrt: {
        ...dreamingwrt,
        signature_update: { ...signatureUpdateSource },
        accent_color: dreamingwrt.accent_color || 'violet',
        glass_opacity: finiteNumber(materialSource.neutral_density, finiteNumber(dreamingwrt.glass_opacity, 0.06)),
        glass_highlight: finiteNumber(materialSource.highlight, finiteNumber(dreamingwrt.glass_highlight, 0.28)),
        glass_blur: finiteNumber(materialSource.base_blur, finiteNumber(dreamingwrt.glass_blur, 3.2)),
        glass_saturate: finiteNumber(materialSource.saturation, finiteNumber(dreamingwrt.glass_saturate, 140)),
        material_glass: {
          ...materialSource,
          version: 1,
          mode: ['shader', 'standard', 'prominent', 'polar'].includes(materialSource.mode) ? materialSource.mode : (menuGlassSource.mode || 'shader'),
          base_blur: finiteNumber(materialSource.base_blur, finiteNumber(dreamingwrt.glass_blur, 3.2)),
          neutral_density: finiteNumber(materialSource.neutral_density, finiteNumber(dreamingwrt.glass_opacity, 0.06)),
          neutral_color: materialSource.neutral_color || '10 16 25',
          saturation: finiteNumber(materialSource.saturation, finiteNumber(dreamingwrt.glass_saturate, 140)),
          displacement_scale: finiteNumber(materialSource.displacement_scale, finiteNumber(menuGlassSource.displacement_scale, 80)),
          aberration_intensity: finiteNumber(materialSource.aberration_intensity, finiteNumber(menuGlassSource.aberration_intensity, 2)),
          border_width: finiteNumber(materialSource.border_width, 1),
          border_color: materialSource.border_color || '#25FFFFFF',
          highlight: finiteNumber(materialSource.highlight, finiteNumber(dreamingwrt.glass_highlight, 0.28)),
          highlight_angle: finiteNumber(materialSource.highlight_angle, finiteNumber(menuGlassSource.highlight_angle, 135)),
          preserve_center: materialSource.preserve_center !== false
        },
        menu_liquid_glass: {
          ...menuGlassSource,
          mode: ['shader', 'standard', 'prominent', 'polar'].includes(menuGlassSource.mode) ? menuGlassSource.mode : 'shader',
          displacement_scale: finiteNumber(menuGlassSource.displacement_scale, 80),
          blur_amount: finiteNumber(menuGlassSource.blur_amount, 0),
          saturation: finiteNumber(menuGlassSource.saturation, 140),
          aberration_intensity: finiteNumber(menuGlassSource.aberration_intensity, 2),
          corner_radius: finiteNumber(menuGlassSource.corner_radius, 0),
          over_light: Boolean(menuGlassSource.over_light),
          highlight_angle: finiteNumber(menuGlassSource.highlight_angle, 135)
        },
        ui_mode: dreamingwrt.ui_mode || 'glass',
        sidebar_collapsed: dreamingwrt.sidebar_collapsed !== false,
        wallpaper: {
          ...wallpaperSource,
          enabled: Boolean(wallpaperSource.enabled),
          directory: wallpaperSource.directory || '/www/dreamingwrt/static/background',
          image: stringOr(wallpaperSource.image),
          opacity: finiteNumber(wallpaperSource.opacity, 0.16),
          mode: wallpaperSource.mode || 'argon',
          interval: wallpaperSource.interval || 'medium',
          login_enabled: wallpaperSource.login_enabled !== false,
          login_image: stringOr(wallpaperSource.login_image),
          login_opacity: finiteNumber(wallpaperSource.login_opacity, 1),
          login_mode: wallpaperSource.login_mode || 'argon',
          login_interval: wallpaperSource.login_interval || 'medium'
        },
        dashboard: {
          ...dashboardSource,
          default_view: dashboardSource.default_view || 'overview',
          show_status_rail: dashboardSource.show_status_rail !== false,
          animation_level: dashboardSource.animation_level || 'balanced',
          density: dashboardSource.density || 'comfortable'
        }
      },
      capabilities: data.capabilities && typeof data.capabilities === 'object' ? data.capabilities : {}
    };
  }

  function stringOr(value) {
    return value === undefined || value === null ? '' : String(value);
  }

  function finiteNumber(value, fallback) {
    const number = Number(value);
    return Number.isFinite(number) ? number : fallback;
  }

  function formatBytes(value) {
    const n = Number(value || 0);
    if (!Number.isFinite(n) || n <= 0) return '';
    const units = ['B', 'KB', 'MB', 'GB', 'TB', 'PB'];
    let size = n;
    let index = 0;
    while (size >= 1024 && index < units.length - 1) {
      size /= 1024;
      index += 1;
    }
    const fixed = size >= 100 || index === 0 ? 0 : size >= 10 ? 1 : 2;
    return `${size.toFixed(fixed)} ${units[index]}`;
  }

  function systemNtpServers(g = {}) {
    if (Array.isArray(g.ntp_servers)) return g.ntp_servers.length ? g.ntp_servers.map(stringOr) : [''];
    if (typeof g.ntp_servers_text === 'string' && g.ntp_servers_text.trim()) {
      return g.ntp_servers_text.split(/\r?\n/).map((item) => item.trim()).filter(Boolean);
    }
    return ['ntp1.aliyun.com', 'ntp2.aliyun.com', 'time1.cloud.tencent.com'];
  }

  function render() {
    if (!root || !state.mounted) return;
    const scrollSnapshot = captureScrollState();
    const focusSnapshot = captureSystemFocus();
    root.className = `${root.className.split(/\s+/).filter((item) => item && item !== MODULE_CLASS).join(' ')} ${MODULE_CLASS}`.trim();
    root.hidden = false;
    root.innerHTML = `
      <div class="system-settings-layout system-settings-layout-${escapeHtml(page)} ${page === 'admin' ? 'system-settings-layout-admin' : ''}">
        ${systemLoadingStatus()}
        ${systemCurrentPanel(state.data)}
        ${systemBindingDialog()}
        ${systemSettingsSavebar()}
      </div>
    `;
    bindCurrentFields();
    updateClockText();
    ui.mountAll?.(root);
    restoreSystemFocus(focusSnapshot);
    ui.scheduleGlassCardsRender?.(160);
    restoreScrollState(scrollSnapshot);
    if (state.bindingDialog) focusBindingDialog();
  }

  function systemCurrentPanel(data) {
    if (page === 'admin') return systemAdminPanel(data);
    if (page === 'startup') return systemStartupPanel(data);
    if (page === 'crontab') return systemCrontabPanel(data);
    if (page === 'mounts') return systemMountsPanel(data);
    if (page === 'advanced') return systemAdvancedPanel(data);
    if (page === 'flash') return systemFlashPanel(data);
    return systemGeneralPanel(data);
  }

  function systemGeneralPanel(data) {
    const tab = SYSTEM_GENERAL_TABS.find((item) => item.id === state.tab) || SYSTEM_GENERAL_TABS[0];
    return `
      <div class="system-general-workspace">
        <nav class="dwrt-kit-tabs dwrt-kit-page-tabs system-general-tabs" role="tablist" aria-label="系统常规设置">
          <span class="dwrt-kit-tab-pill" aria-hidden="true"></span>
          ${SYSTEM_GENERAL_TABS.map((item) => `
            <button class="dwrt-kit-tab ${tab.id === item.id ? 'is-active' : ''}" type="button" role="tab" aria-selected="${tab.id === item.id ? 'true' : 'false'}" data-value="${escapeHtml(item.id)}" data-system-general-tab="${escapeHtml(item.id)}">
              ${escapeHtml(item.label)}
            </button>
          `).join('')}
        </nav>
        <div class="system-general-content ${tab.id === 'logs' ? 'wide' : ''}">
          ${renderSystemGeneralTab(data, tab.id)}
        </div>
      </div>
    `;
  }

  function loadingPanel(label = '系统设置') {
    return `
      <section class="system-demo-panel system-loading-panel">
        <div class="system-demo-panel-title">${systemSettingsIcon('sync')}<span>正在读取</span></div>
        <div class="system-loading-text">读取${escapeHtml(label)}…</div>
      </section>
    `;
  }

  function renderSystemGeneralTab(data, tab) {
    const error = state.error ? `<div class="system-inline-error">${escapeHtml(state.error)}</div>` : '';
    if (tab === 'logs') return `${error}${systemGeneralLogsPanel(data)}`;
    if (tab === 'time') return `${error}${systemGeneralTimePanel(data)}`;
    if (tab === 'zram') return `${error}${systemGeneralZramPanel(data)}`;
    return `${error}${systemGeneralDemoPanel(data)}`;
  }

  function systemGeneralDemoPanel(data) {
    const g = data.general || {};
    const description = Object.prototype.hasOwnProperty.call(g, 'description') ? g.description : (g.model || '');
    return `
      <div class="system-general-card-grid">
        <section class="system-demo-panel">
          <div class="system-demo-panel-title">${systemSettingsIcon('identity')}<span>设备身份</span></div>
          ${systemSettingsRow('主机名', systemInputControl('general.hostname', g.hostname))}
          ${systemSettingsRow('描述', `${systemInputControl('general.description', description)}<span class="system-input-hint">此设备的简短描述信息</span>`)}
          ${systemSettingsRow('备注', systemTextareaControl('general.note', g.note ?? '', '请输入任意格式的备注...'), 'top')}
        </section>
        <section class="system-demo-panel">
          <div class="system-demo-panel-title">${systemSettingsIcon('clock')}<span>时间与同步</span></div>
          ${systemSettingsRow('本地时间', `
            <div class="system-time-sync-row">
              <div class="system-time-display" data-system-clock>${escapeHtml(systemLocalTimeText(g))}</div>
              <div class="system-demo-button-group">
                <button class="system-demo-btn primary" type="button" data-system-action="sync-browser-time">与浏览器同步</button>
                <button class="system-demo-btn secondary" type="button" data-system-action="sync-ntp-time">与 NTP 服务同步</button>
              </div>
            </div>
          `)}
          ${systemSettingsRow('时区', systemSelectControl('general.timezone', g.timezone || 'Asia/Shanghai', systemTimezoneOptions()))}
          ${systemSettingsRow('时间格式', systemSelectControl('general.time_format', g.time_format || '24h', [['24h', '默认（24小时制）'], ['12h', '12小时制（AM/PM）']]))}
          ${systemSettingsRow('', `
            <label class="system-demo-check glass-check-label">
              <input type="checkbox" ${g.show_timezone_name !== false ? 'checked' : ''} data-system-field="general.show_timezone_name">
              <span class="glass-check-box" aria-hidden="true"></span>
              <span>显示完整时区名</span>
            </label>
            <span class="system-input-hint">取消勾选表示显示时区偏移（如 GMT+8）</span>
          `)}
        </section>
      </div>
      <section class="system-demo-panel system-preference-panel">
        <div class="system-demo-panel-title">${systemSettingsIcon('language')}<span>语言</span></div>
        ${systemPreferenceItem('language', '界面语言', systemSelectControl('general.language', g.language || 'auto', [['auto', '自动（跟随浏览器）'], ['zh-cn', '简体中文'], ['en', 'English']], 'glass-select'))}
      </section>
    `;
  }

  function systemGeneralLogsPanel(data) {
    const g = data.general || {};
    const sysLevel = g.log_level || 'warning';
    return `
      <div class="system-general-card-grid system-log-card-grid">
        <section class="system-demo-panel system-log-panel">
          <div class="system-demo-panel-title">${systemSettingsIcon('terminal')}<span>本地日志记录</span></div>
          ${systemSettingsRow('日志缓冲区大小', `${systemInputControl('general.log_buffer_kb', g.log_buffer_kb || 128, 'number')}<span class="system-unit-label">KiB</span>`, 'center', 'wide-label inline-control')}
          ${systemSettingsRow('系统日志记录级别', `
            ${systemSelectControl('general.log_level', sysLevel, systemLogLevelOptions(), 'level-select')}
            ${systemLevelBadge(sysLevel)}
          `, 'center', 'wide-label inline-control')}
          ${systemSettingsRow('计划任务日志级别', systemSelectControl('general.cron_log_level', g.cron_log_level || 'error', [['disabled', '已禁用'], ['error', '仅记录错误'], ['all', '全部记录']]), 'center', 'wide-label')}
        </section>
        <section class="system-demo-panel system-log-panel">
          <div class="system-demo-panel-title">${systemSettingsIcon('globe')}<span>外部系统日志 (Syslog)</span></div>
          ${systemSettingsRow('外部服务器地址', systemInputControl('general.remote_log_host', g.remote_log_host || '', 'text', '0.0.0.0'), 'center', 'wide-label')}
          ${systemSettingsRow('外部服务器端口', `${systemInputControl('general.remote_log_port', g.remote_log_port || 514, 'number')}<span class="system-demo-spacer"></span>`, 'center', 'wide-label port-row')}
          ${systemSettingsRow('外部服务器协议', systemSegmentedControl('general.remote_log_protocol', g.remote_log_protocol || 'udp', [['udp', 'UDP'], ['tcp', 'TCP']]), 'center', 'wide-label')}
        </section>
      </div>
      <section class="system-demo-panel system-log-panel">
        <div class="system-demo-panel-title">${systemSettingsIcon('disk')}<span>日志文件同步</span></div>
        ${systemSettingsRow('写入文件路径', systemInputControl('general.log_file_path', g.log_file_path || '/tmp/system.log'), 'center', 'wide-label')}
        <div class="system-demo-warning">注意：将日志持续写入闪存可能会缩短设备寿命，建议使用 /tmp（内存）或外部存储。</div>
      </section>
    `;
  }

  function systemGeneralTimePanel(data) {
    const g = data.general || {};
    const servers = systemNtpServers(g);
    return `
      <section class="system-demo-panel system-time-control-panel">
        <div class="system-demo-panel-title">${systemSettingsIcon('gear')}<span>服务控制</span></div>
        ${systemSettingsItem('启用 NTP 客户端', systemIosSwitch('general.time_sync', g.time_sync !== false))}
        ${systemSettingsItem('作为 NTP 服务器提供服务', systemIosSwitch('general.ntp_server_enabled', Boolean(g.ntp_server_enabled)))}
        ${systemSettingsItem('使用 DHCP 通告的服务器', systemIosSwitch('general.ntp_use_dhcp', g.ntp_use_dhcp !== false))}
      </section>
      <section class="system-demo-panel system-ntp-panel">
        <div class="system-demo-panel-title">${systemSettingsIcon('hourglass')}<span>候选 NTP 服务器</span></div>
        <div class="system-server-list">
          ${servers.map((server, index) => systemServerItem(index, server)).join('')}
        </div>
        <div class="system-server-add-row">
          <button class="system-circle-btn add" type="button" data-system-action="ntp-add">+</button>
          <span>添加服务器</span>
        </div>
        <div class="system-input-hint padded">候选的上游 NTP 服务器列表，用于同步本设备时间。</div>
      </section>
    `;
  }

  function systemFlashPanel(data) {
    const tab = SYSTEM_FLASH_TABS.find((item) => item.id === state.flashTab) || SYSTEM_FLASH_TABS[0];
    return `
      <div class="system-flash-workspace">
        <nav class="dwrt-kit-tabs dwrt-kit-page-tabs system-general-tabs system-flash-tabs" role="tablist" aria-label="备份与升级">
          <span class="dwrt-kit-tab-pill" aria-hidden="true"></span>
          ${SYSTEM_FLASH_TABS.map((item) => `
            <button class="dwrt-kit-tab ${tab.id === item.id ? 'is-active' : ''}" type="button" role="tab" aria-selected="${tab.id === item.id ? 'true' : 'false'}" data-value="${escapeHtml(item.id)}" data-system-flash-tab="${escapeHtml(item.id)}">
              ${escapeHtml(item.label)}
            </button>
          `).join('')}
        </nav>
        <div class="system-flash-content">
          ${renderSystemFlashTab(data, tab.id)}
        </div>
      </div>
    `;
  }

  function renderSystemFlashTab(data, tab) {
    if (tab === 'config') return systemFlashConfigPanel(data);
    return systemFlashOperationsPanel(data);
  }

  function flashCapability(name) {
    return (state.data.capabilities || {})[name] === true;
  }

  function flashStatusMessage() {
    if (!state.flashError && !state.flashMessage) return '';
    return `<div class="system-flash-status ${state.flashError ? 'is-error' : 'is-success'}" role="status">${escapeHtml(state.flashError || state.flashMessage)}</div>`;
  }

  function systemFlashOperationsPanel(data) {
    const f = data.flash || {};
    const canCreate = flashCapability('flash_backup_create');
    const canRestore = flashCapability('flash_backup_restore') && flashCapability('flash_browser_upload');
    const canUpgrade = flashCapability('flash_sysupgrade') && flashCapability('flash_browser_upload');
    const canReset = flashCapability('flash_factory_reset');
    const backupFile = state.flashBackupFile;
    const firmwareFile = state.flashFirmwareFile;
    const busy = Boolean(state.flashWorking);
    return `
      <div class="system-flash-page">
        ${state.error ? `<div class="system-inline-error">${escapeHtml(state.error)}</div>` : ''}
        ${flashStatusMessage()}
        <div class="system-flash-action-grid">
          ${systemFlashActionCard({
            icon: 'download',
            title: '下载备份',
            description: '生成当前配置的备份存档。建议在升级固件或修改关键网络设置前执行。',
            meta: f.last_backup_at ? `最近生成：${formatTimestamp(f.last_backup_at)}${f.backup_size ? ` · ${f.backup_size}` : ''}` : '尚未生成备份',
            action: 'flash-create-backup',
            actionText: state.flashWorking === 'create-backup' ? '正在生成…' : '生成备份',
            disabled: busy || !canCreate,
            unavailable: !canCreate ? '后端尚未开放备份生成能力' : ''
          })}
          <section class="system-demo-panel system-flash-action-card is-restore">
            <span class="system-flash-card-icon" aria-hidden="true">${systemSettingsIcon('restore')}</span>
            <div class="system-flash-card-copy">
              <strong>恢复配置</strong>
              <p>选择由本设备生成的备份存档。恢复会覆盖当前配置，并可能触发设备重启。</p>
            </div>
            <label class="system-flash-file-picker">
              <input type="file" accept=".tar,.gz,.tgz,.tar.gz,application/gzip,application/x-gzip" data-system-flash-file="backup">
              <span>${systemSettingsIcon('upload')}<b>${backupFile ? escapeHtml(backupFile.name) : '选择备份存档'}</b></span>
              ${backupFile ? `<em>${escapeHtml(formatBytes(backupFile.size) || '大小未知')}</em>` : ''}
            </label>
            <button class="glass-btn glass-btn--primary" type="button" data-system-action="flash-restore-backup" ${busy || !backupFile || !canRestore ? 'disabled' : ''}>恢复配置</button>
            ${!canRestore ? '<small class="system-flash-capability-note">需要后端提供浏览器上传暂存合同后才能恢复。</small>' : ''}
          </section>
        </div>

        <section class="system-demo-panel system-flash-firmware-panel">
          <div class="system-flash-version-block">
            <span>当前版本</span>
            <strong>${escapeHtml(systemFlashVersionLabel(f.current_firmware || data.general?.version || 'Dreaming OS'))}</strong>
            <em>${escapeHtml(systemFlashBuildLabel(f))}</em>
          </div>
          <div class="system-flash-firmware-actions">
            <div class="system-flash-card-copy">
              <strong>刷写新的固件镜像</strong>
              <p>选择兼容的 sysupgrade 镜像。执行前应先生成并下载配置备份。</p>
            </div>
            <label class="system-flash-file-picker wide">
              <input type="file" accept=".bin,.img,.itb,application/octet-stream" data-system-flash-file="firmware">
              <span>${systemSettingsIcon('upload')}<b>${firmwareFile ? escapeHtml(firmwareFile.name) : '选择固件镜像'}</b></span>
              ${firmwareFile ? `<em>${escapeHtml(formatBytes(firmwareFile.size) || '大小未知')}</em>` : ''}
            </label>
            <label class="system-flash-keep-settings">
              <input type="checkbox" ${(state.flashKeepSettings ?? f.keep_settings) !== false ? 'checked' : ''} data-system-flash-keep-settings>
              <span class="glass-check-box" aria-hidden="true"></span>
              <span>升级时保留当前配置</span>
            </label>
            <button class="glass-btn glass-btn--primary" type="button" data-system-action="flash-sysupgrade" ${busy || !firmwareFile || !canUpgrade ? 'disabled' : ''}>${state.flashConfirm === 'sysupgrade' ? '再次点击确认升级' : '上传并刷写固件'}</button>
            ${!canUpgrade ? '<small class="system-flash-capability-note">浏览器上传、固件兼容性校验和升级进度合同尚未开放。</small>' : ''}
          </div>
        </section>

        <section class="system-demo-panel system-flash-danger-panel">
          <span class="system-flash-danger-icon" aria-hidden="true">${systemSettingsIcon('warning')}</span>
          <div>
            <strong>恢复出厂设置</strong>
            <p>清除设备上的自定义配置并重新启动。该操作无法撤销。</p>
          </div>
          <button class="glass-btn system-flash-danger-button" type="button" data-system-action="flash-factory-reset" ${busy || !canReset ? 'disabled' : ''}>${state.flashConfirm === 'factory-reset' ? '再次点击确认重置' : '恢复出厂设置'}</button>
          ${!canReset ? '<small class="system-flash-capability-note">当前后端未开放恢复出厂设置能力。</small>' : ''}
        </section>
        ${systemSignatureUpdateCard(data)}
      </div>
    `;
  }

  function systemSignatureUpdateCard(data = {}) {
    const info = systemSignatureUpdateInfo(data);
    const selected = state.signatureUpdateFile;
    const backendReady = info.backend_ready;
    const status = state.signatureUpdateStatus || info.status;
    return `
      <section class="system-demo-panel system-signature-card">
        <header class="system-signature-header">
          <div class="system-demo-panel-title">${systemSettingsIcon('database')}<span>特征库更新</span></div>
          <em class="system-signature-status ${backendReady ? 'ready' : 'pending'}">${backendReady ? '后端可应用' : '等待 Web 上传接口'}</em>
        </header>
        <div class="system-signature-summary">
          ${systemSignatureMetric('应用数量', info.apps)}
          ${systemSignatureMetric('DPI 特征', info.rules)}
          ${systemSignatureMetric('域名条目', info.domains)}
          ${systemSignatureMetric('图标资源', info.icons)}
        </div>
        <div class="system-signature-meta-grid">
          <span><b>构建日期</b><em>${escapeHtml(info.build_date || '后端未返回')}</em></span>
          <span><b>数据库</b><em>${escapeHtml(info.db_source || 'dreamingwrt_signatures.db')}</em></span>
          <span><b>包格式</b><em>signature-update-v1/v2 · .bin</em></span>
          <span><b>运行状态</b><em>${escapeHtml(systemSignaturePhaseLabel(info.phase))}</em></span>
        </div>
        <div class="system-signature-upload">
          <label class="system-signature-file-picker">
            <input type="file" accept=".bin,application/octet-stream" data-system-signature-upload>
            <span>${systemSettingsIcon('upload')}<b>${selected ? escapeHtml(selected.name) : '选择特征库更新包'}</b></span>
            ${selected ? `<em>${escapeHtml(formatBytes(selected.size) || '大小未知')}</em>` : ''}
          </label>
          <button class="glass-btn glass-btn--primary" type="button" data-system-action="signature-apply-package" ${!selected || !backendReady || state.flashWorking ? 'disabled' : ''}>${state.flashWorking === 'signature-apply' ? '应用中…' : '校验并应用'}</button>
          <span class="system-signature-file">${selected ? '已选择更新包，应用前将由后端校验格式、数据库和图标资源。' : '请选择 tools/package-signature-update.sh 生成的 .bin 文件。'}</span>
        </div>
        ${status?.message ? `<p class="system-signature-note ${escapeHtml(status.kind || '')}">${escapeHtml(status.message)}</p>` : ''}
      </section>
    `;
  }

  function systemSignatureMetric(label, value) {
    const missing = value === undefined || value === null || value === '';
    const number = Number(value);
    const text = missing ? '--' : (Number.isFinite(number) ? formatInteger(number) : String(value));
    return `<span class="system-signature-metric"><b>${escapeHtml(text)}</b><em>${escapeHtml(label)}</em></span>`;
  }

  function systemSignatureUpdateInfo(data = {}) {
    const runtime = data?.dreamingwrt?.signature_update || {};
    const counts = runtime.counts || runtime.status?.counts || {};
    const meta = runtime.meta || runtime.status?.meta || {};
    return {
      apps: counts.apps ?? runtime.apps ?? null,
      rules: counts.dpi_rules ?? counts.rules ?? runtime.rules ?? null,
      domains: counts.domain_entries ?? counts.domains ?? runtime.domains ?? null,
      icons: counts.icons ?? runtime.icons ?? null,
      build_date: stringOr(meta.build_date || meta.built_at || meta.created_at || runtime.build_date),
      db_source: stringOr(runtime.path || runtime.source || 'dreamingwrt_signatures.db'),
      backend_ready: Boolean(runtime.backend_ready && runtime.browser_upload_endpoint && runtime.apply_endpoint),
      phase: stringOr(runtime.phase || runtime.status?.phase),
      status: runtime.status && typeof runtime.status === 'object' ? runtime.status : null
    };
  }

  function systemSignaturePhaseLabel(value) {
    const labels = { validating: '正在校验', validated: '校验通过', applying: '正在应用', applied: '已应用', validation_failed: '校验失败', apply_failed: '应用失败' };
    return labels[String(value || '')] || (value ? String(value) : '空闲');
  }

  function systemFlashActionCard({ icon, title, description, meta, action, actionText, disabled, unavailable }) {
    return `
      <section class="system-demo-panel system-flash-action-card is-${escapeHtml(icon)}">
        <span class="system-flash-card-icon" aria-hidden="true">${systemSettingsIcon(icon)}</span>
        <div class="system-flash-card-copy">
          <strong>${escapeHtml(title)}</strong>
          <p>${escapeHtml(description)}</p>
        </div>
        <em class="system-flash-card-meta">${escapeHtml(meta)}</em>
        <button class="glass-btn glass-btn--primary" type="button" data-system-action="${escapeHtml(action)}" ${disabled ? 'disabled' : ''}>${escapeHtml(actionText)}</button>
        ${unavailable ? `<small class="system-flash-capability-note">${escapeHtml(unavailable)}</small>` : ''}
      </section>
    `;
  }

  function systemFlashConfigPanel() {
    const text = state.flashPreserveText;
    const lineCount = Math.max(10, String(text || '').split(/\r?\n/).length);
    const canSave = state.flashPreserveAvailable && !state.flashPreserveLoading;
    return `
      <div class="system-flash-config-page">
        ${flashStatusMessage()}
        <section class="system-demo-panel system-flash-config-panel">
          <header class="system-flash-config-header">
            <div>
              <div class="system-demo-panel-title">${systemSettingsIcon('file')}<span>保留配置清单</span></div>
              <p>每行填写一个升级时需要保留的绝对路径。<code>/etc/config/</code> 中已修改的配置会由 sysupgrade 自动处理。</p>
            </div>
            <code>${escapeHtml(state.flashPreservePath || '/etc/sysupgrade.conf')}</code>
          </header>
          <div class="system-code-editor-container system-flash-editor-container">
            <div class="system-code-line-numbers" aria-hidden="true">${Array.from({ length: lineCount }, (_, index) => `<div>${index + 1}</div>`).join('')}</div>
            <textarea class="system-code-editor" spellcheck="false" data-system-flash-preserve data-system-scroll="flash-preserve-editor" data-system-scroll-sync="flash-preserve-editor" ${canSave ? '' : 'disabled'}>${escapeHtml(text)}</textarea>
          </div>
          <footer class="system-flash-config-footer">
            <span>${state.flashPreserveLoading ? '正在读取保留清单…' : state.flashPreserveAvailable ? '仅绝对路径会被保存。空行和注释不会写入。' : '当前后端没有返回保留清单，编辑器保持只读。'}</span>
            <button class="glass-btn glass-btn--primary" type="button" data-system-action="flash-save-preserve" ${!canSave || state.flashWorking ? 'disabled' : ''}>${state.flashWorking === 'save-preserve' ? '保存中…' : '保存清单'}</button>
          </footer>
        </section>
      </div>
    `;
  }

  function formatTimestamp(value) {
    const n = Number(value || 0);
    if (!n) return '';
    try { return new Intl.DateTimeFormat('zh-CN', { dateStyle: 'medium', timeStyle: 'short' }).format(new Date(n > 1e12 ? n : n * 1000)); }
    catch (_) { return String(value); }
  }

  function systemFlashVersionLabel(value) {
    const raw = String(value || '').trim();
    const description = raw.match(/DISTRIB_DESCRIPTION\s*=\s*['"]([^'"]+)['"]/i);
    if (description) return description[1].trim();
    const id = raw.match(/DISTRIB_ID\s*=\s*['"]?([^'"\r\n]+)['"]?/i);
    if (id) return id[1].trim();
    return raw || 'Dreaming OS';
  }

  function systemFlashBuildLabel(f = {}) {
    const build = String(f.build_time || '').trim();
    if (build) return build;
    const kernel = String(f.kernel || '').trim();
    const version = kernel.match(/Linux version\s+(\S+)/i);
    return version ? `Linux ${version[1]}` : (kernel || '未返回构建信息');
  }

  function systemGeneralZramPanel(data) {
    const a = data.advanced || {};
    const physicalMb = Number(a.memory_total_mb || 512);
    const zramMb = Number(a.zram_size_mb || 256);
    const zramPercent = Math.max(8, Math.min(70, (zramMb / Math.max(physicalMb + zramMb, 1)) * 100));
    const physicalPercent = Math.max(20, Math.min(82, 100 - zramPercent - 10));
    return `
      <section class="system-demo-panel system-zram-panel">
        <div class="system-demo-panel-title">${systemSettingsIcon('zram')}<span>ZRam 性能优化</span></div>
        <div class="system-mem-preview">
          <div class="system-mem-bar physical" style="width:${physicalPercent}%"></div>
          <div class="system-mem-bar zram" style="width:${zramPercent}%"></div>
        </div>
        <div class="system-mem-legend">
          <span><i class="physical"></i>物理内存（${formatInteger(physicalMb)}MB）</span>
          <span><i class="zram"></i>ZRam 交换区（${formatInteger(zramMb)}MB）</span>
        </div>
        ${systemZramItem('ZRam 大小', '虚拟内存设备的大小（建议设为物理内存的 50%-100%）', `<div class="system-field-wrap">${systemInputControl('advanced.zram_size_mb', zramMb, 'number')}<span class="system-field-unit">MiB</span></div>`)}
        ${systemZramItem('压缩算法', 'lz4 速度最快，zstd 压缩率最高', `<div class="system-field-wrap select-arrow">${systemSelectControl('advanced.zram_algorithm', a.zram_algorithm || 'lz4', [['lzo', 'lzo'], ['lz4', 'lz4（推荐）'], ['zstd', 'zstd（平衡）'], ['deflate', 'deflate']])}</div>`)}
      </section>
    `;
  }

  function systemAdvancedPanel(data) {
    const tab = SYSTEM_ADVANCED_TABS.find((item) => item.id === state.advancedTab) || SYSTEM_ADVANCED_TABS[0];
    const advanced = data.advanced || {};
    return `
      <div class="system-advanced-workspace">
        <nav class="dwrt-kit-tabs dwrt-kit-page-tabs system-general-tabs system-advanced-tabs" role="tablist" aria-label="系统高级设置">
          <span class="dwrt-kit-tab-pill" aria-hidden="true"></span>
          ${SYSTEM_ADVANCED_TABS.map((item) => `
            <button class="dwrt-kit-tab ${tab.id === item.id ? 'is-active' : ''}" type="button" role="tab" aria-selected="${tab.id === item.id ? 'true' : 'false'}" data-value="${escapeHtml(item.id)}" data-system-advanced-tab="${escapeHtml(item.id)}">${escapeHtml(item.label)}</button>
          `).join('')}
        </nav>
        <div class="system-advanced-content">
          ${state.error ? `<div class="system-inline-error">${escapeHtml(state.error)}</div>` : ''}${renderSystemAdvancedTab(advanced, tab.id)}
        </div>
      </div>
    `;
  }

  function renderSystemAdvancedTab(advanced, tab) {
    if (tab === 'alg') return systemAdvancedAlgPanel(advanced);
    if (tab === 'cpu') return systemAdvancedCpuPanel(advanced);
    if (tab === 'kernel') return systemAdvancedKernelPanel(advanced);
    return systemAdvancedPerformancePanel(advanced);
  }

  function systemAdvancedPerformancePanel(a = {}) {
    return `
      <section class="system-demo-panel system-advanced-panel">
        <div class="system-advanced-title">${systemSettingsIcon('rocket')}<span>内核性能优化</span></div>
        <div class="system-advanced-hero-grid">
          ${systemAdvancedHeroCard('Packet Steering', '在多核心 CPU 间分发网卡软中断，提升小包吞吐量', 'advanced.packet_steering', Boolean(a.packet_steering), 'antenna')}
          ${systemAdvancedHeroCard('IRQ Balance', '自动优化硬件中断分配，降低单核负载压力', 'advanced.irq_balance', Boolean(a.irq_balance), 'balance')}
          ${systemAdvancedHeroCard('内核精简模式', '禁用非必要的内核模块以节省系统资源', 'advanced.kernel_slim_mode', Boolean(a.kernel_slim_mode), 'tools')}
        </div>
        <div class="system-advanced-well">
          ${systemAdvancedSelect('Flow Offloading（流量分载）', 'advanced.flow_offloading', a.flow_offloading || 'off', [['software', '软件分载'], ['hardware', '硬件分载'], ['off', '关闭']])}
          ${systemAdvancedSelect('调度优先级', 'advanced.scheduler_priority', a.scheduler_priority || 'normal', [['rt', '实时优先'], ['normal', '默认平衡']])}
        </div>
      </section>
      <section class="system-demo-panel system-advanced-panel">
        <div class="system-advanced-title">${systemSettingsIcon('lab')}<span>诊断与调试</span></div>
        <div class="system-advanced-debug-grid">
          ${systemAdvancedDebugTile('诊断采集', '收集底层运行日志用于故障排查', 'advanced.collect_diagnostics', Boolean(a.collect_diagnostics))}
          ${systemAdvancedDebugTile('Crash Dump', '系统崩溃时保留现场内存镜像', 'advanced.crash_dump', Boolean(a.crash_dump))}
        </div>
      </section>
    `;
  }

  function systemAdvancedAlgPanel(a = {}) {
    return `
      <section class="system-demo-panel system-advanced-panel">
        <div class="system-advanced-title">${systemSettingsIcon('route')}<span>ALG 协议设置</span></div>
        <div class="system-advanced-debug-grid">
          ${systemAdvancedDebugTile('FTP ALG', '允许 FTP 控制连接触发相关数据连接跟踪', 'advanced.alg_ftp', a.alg_ftp !== false)}
          ${systemAdvancedDebugTile('TFTP ALG', '允许 TFTP 会话通过连接跟踪辅助 NAT', 'advanced.alg_tftp', a.alg_tftp !== false)}
          ${systemAdvancedDebugTile('SIP ALG', '处理 SIP 信令中的地址和端口改写', 'advanced.alg_sip', a.alg_sip !== false)}
          ${systemAdvancedDebugTile('H323 ALG', '处理 H.323 语音视频会话辅助穿透', 'advanced.alg_h323', a.alg_h323 !== false)}
        </div>
      </section>
      <section class="system-demo-panel system-advanced-panel">
        <div class="system-advanced-title">${systemSettingsIcon('tools')}<span>非标准端口</span></div>
        <div class="system-advanced-well system-advanced-port-grid">
          ${systemAdvancedTextField('FTP 非标准端口（可选）', 'advanced.alg_ftp_ports', a.alg_ftp_ports || '', '例如：2121,2122')}
          ${systemAdvancedTextField('TFTP 非标准端口（可选）', 'advanced.alg_tftp_ports', a.alg_tftp_ports || '', '例如：6969,6970')}
          ${systemAdvancedTextField('SIP 非标准端口（可选）', 'advanced.alg_sip_ports', a.alg_sip_ports || '', '例如：5061,5062')}
        </div>
      </section>
    `;
  }

  function systemAdvancedCpuPanel(a = {}) {
    const cpus = Array.isArray(a.cpu_interrupts) ? a.cpu_interrupts : [];
    const nics = Array.isArray(a.nic_interrupts) ? a.nic_interrupts : [];
    return `
      <section class="dwrt-kit-table-wrap system-table-card system-advanced-table-card">
        <div class="dwrt-kit-table-toolbar">
          <div class="dwrt-kit-table-title"><strong>CPU 中断</strong><span>查看 CPU 频率、负载和软硬中断状态</span></div>
          <span class="dwrt-kit-table-count">${formatInteger(cpus.length)} 个 CPU</span>
        </div>
        <div class="dwrt-kit-table-scroll system-advanced-table-scroll" data-system-scroll="advanced-cpu-table">
          <table class="dwrt-kit-table system-advanced-cpu-table" aria-label="CPU 中断">
            <thead><tr>${['CPU ID', '当前频率', '使用率', '物理 ID', '核心 ID', '软中断', '硬中断', '操作'].map((item) => `<th scope="col">${escapeHtml(item)}</th>`).join('')}</tr></thead>
            <tbody>${cpus.length ? cpus.map(systemAdvancedCpuRow).join('') : '<tr><td colspan="8" class="dwrt-kit-table-empty">等待后端返回 CPU 中断状态。</td></tr>'}</tbody>
          </table>
        </div>
      </section>
      <section class="dwrt-kit-table-wrap system-table-card system-advanced-table-card">
        <div class="dwrt-kit-table-toolbar">
          <div class="dwrt-kit-table-title"><strong>网卡硬中断</strong><span>查看网卡 IRQ、队列和 CPU 亲和性</span></div>
          <span class="dwrt-kit-table-count">${formatInteger(nics.length)} 个队列</span>
        </div>
        <div class="dwrt-kit-table-scroll system-advanced-table-scroll" data-system-scroll="advanced-nic-table">
          <table class="dwrt-kit-table system-advanced-nic-table" aria-label="网卡硬中断">
            <thead><tr>${['网卡', 'IRQ', '队列', 'CPU 亲和性', '状态'].map((item) => `<th scope="col">${escapeHtml(item)}</th>`).join('')}</tr></thead>
            <tbody>${nics.length ? nics.map((item) => `<tr><td>${escapeHtml(item.ifname || item.name || '-')}</td><td>${escapeHtml(item.irq || '-')}</td><td>${escapeHtml(item.queue || '-')}</td><td>${escapeHtml(item.affinity || '-')}</td><td>${systemAdvancedStateBadge(item.enabled !== false)}</td></tr>`).join('') : '<tr><td colspan="5" class="dwrt-kit-table-empty">等待后端返回网卡硬中断状态。</td></tr>'}</tbody>
          </table>
        </div>
      </section>
    `;
  }

  function systemAdvancedCpuRow(cpu) {
    const id = cpu.id ?? cpu.cpu ?? '-';
    const softEnabled = cpu.soft_irq_enabled !== false;
    const hardEnabled = cpu.hard_irq_enabled !== false;
    return `<tr>
      <td>${escapeHtml(`CPU${id}`)}</td><td>${escapeHtml(cpu.frequency || cpu.freq || '-')}</td><td>${escapeHtml(cpu.usage || cpu.usage_percent || '-')}</td><td>${escapeHtml(cpu.physical_id ?? cpu.package_id ?? '-')}</td><td>${escapeHtml(cpu.core_id ?? '-')}</td>
      <td>${systemAdvancedStateBadge(softEnabled)}</td><td>${systemAdvancedStateBadge(hardEnabled)}</td>
      <td><span class="system-advanced-row-actions"><button type="button" disabled title="后端当前只支持 IRQ smp_affinity，未提供 CPU 软中断开关合同">${softEnabled ? '关闭软中断' : '开启软中断'}</button><button type="button" disabled title="后端当前只支持 IRQ smp_affinity，未提供 CPU 硬中断开关合同">${hardEnabled ? '关闭硬中断' : '开启硬中断'}</button></span></td>
    </tr>`;
  }

  function systemAdvancedStateBadge(enabled) {
    return `<span class="system-advanced-state ${enabled ? 'is-on' : 'is-off'}">${enabled ? '开启' : '关闭'}</span>`;
  }

  function systemAdvancedKernelPanel(a = {}) {
    return `
      <section class="system-demo-panel system-advanced-panel">
        <div class="system-advanced-title">${systemSettingsIcon('terminal')}<span>连接设置</span></div>
        <div class="system-advanced-well system-advanced-kernel-grid">
          ${systemAdvancedTextField('TCP Syn Sent 超时（秒）', 'advanced.nf_tcp_syn_sent', a.nf_tcp_syn_sent ?? 120, '默认：5', 'number')}
          ${systemAdvancedTextField('TCP Syn Received 超时（秒）', 'advanced.nf_tcp_syn_recv', a.nf_tcp_syn_recv ?? 60, '默认：5', 'number')}
          ${systemAdvancedTextField('TCP Established 超时（秒）', 'advanced.nf_tcp_established', a.nf_tcp_established ?? 7440, '默认：1800', 'number')}
          ${systemAdvancedTextField('TCP Fin Wait 超时（秒）', 'advanced.nf_tcp_fin_wait', a.nf_tcp_fin_wait ?? 120, '默认：10', 'number')}
          ${systemAdvancedTextField('TCP Close Wait 超时（秒）', 'advanced.nf_tcp_close_wait', a.nf_tcp_close_wait ?? 60, '默认：10', 'number')}
          ${systemAdvancedTextField('TCP Last Ack 超时（秒）', 'advanced.nf_tcp_last_ack', a.nf_tcp_last_ack ?? 30, '默认：10', 'number')}
          ${systemAdvancedTextField('TCP Time Wait（秒）', 'advanced.nf_tcp_time_wait', a.nf_tcp_time_wait ?? 120, '默认：10', 'number')}
          ${systemAdvancedTextField('TCP Close（秒）', 'advanced.nf_tcp_close', a.nf_tcp_close ?? 10, '默认：5', 'number')}
          ${systemAdvancedTextField('UDP 超时（秒）', 'advanced.nf_udp_timeout', a.nf_udp_timeout ?? 60, '默认：10', 'number')}
          ${systemAdvancedTextField('UDP Stream 超时（秒）', 'advanced.nf_udp_stream', a.nf_udp_stream ?? 180, '默认：60', 'number')}
          ${systemAdvancedTextField('ICMP 超时（秒）', 'advanced.nf_icmp_timeout', a.nf_icmp_timeout ?? 30, '默认：5', 'number')}
        </div>
      </section>
      <section class="system-demo-panel system-advanced-panel">
        <div class="system-advanced-title">${systemSettingsIcon('gear')}<span>参数设置</span></div>
        <div class="system-advanced-debug-grid">${systemAdvancedDebugTile('TCP BBR', '启用 BBR/BBRPlus 拥塞控制与 fq 队列', 'advanced.tcp_bbr', a.tcp_bbr !== false)}</div>
        <div class="system-advanced-footer"><button class="glass-btn glass-btn--ghost" type="button" data-system-action="advanced-kernel-restore-defaults" ${state.operationWorking === 'advanced:kernel-defaults' ? 'disabled' : ''}>${state.operationWorking === 'advanced:kernel-defaults' ? '恢复中…' : '恢复默认配置'}</button></div>
      </section>
    `;
  }

  function systemAdvancedHeroCard(label, desc, field, checked, icon) {
    return `<label class="system-advanced-hero-card ${checked ? 'active' : ''}"><input type="checkbox" ${checked ? 'checked' : ''} data-system-field="${escapeHtml(field)}"><span class="system-advanced-status-box" aria-hidden="true">${systemSettingsIcon(icon)}</span><strong>${escapeHtml(label)}</strong><em>${escapeHtml(desc)}</em></label>`;
  }

  function systemAdvancedSelect(label, field, current, options) {
    return `<label class="system-advanced-field"><span>${escapeHtml(label)}</span><select class="system-advanced-select" data-native-select="true" data-system-field="${escapeHtml(field)}">${options.map(([value, text]) => `<option value="${escapeHtml(value)}" ${String(current) === String(value) ? 'selected' : ''}>${escapeHtml(text)}</option>`).join('')}</select></label>`;
  }

  function systemAdvancedTextField(label, field, value, placeholder = '', type = 'text') {
    return `<label class="system-advanced-field"><span>${escapeHtml(label)}</span><input class="system-advanced-input" type="${escapeHtml(type)}" value="${escapeHtml(value ?? '')}" placeholder="${escapeHtml(placeholder)}" data-system-field="${escapeHtml(field)}"></label>`;
  }

  function systemAdvancedDebugTile(label, desc, field, checked) {
    return `<div class="system-advanced-debug-tile"><span><strong>${escapeHtml(label)}</strong><em>${escapeHtml(desc)}</em></span>${systemIosSwitch(field, checked)}</div>`;
  }


  function systemStartupPanel(data) {
    const tab = SYSTEM_STARTUP_TABS.find((item) => item.id === state.startupTab) || SYSTEM_STARTUP_TABS[0];
    const startup = data.startup || {};
    const error = state.error ? `<div class="system-inline-error">${escapeHtml(state.error)}</div>` : '';
    return `
      <div class="system-page-workspace system-startup-workspace">
        <nav class="dwrt-kit-tabs dwrt-kit-page-tabs system-general-tabs system-startup-tabs" role="tablist" aria-label="启动项">
          <span class="dwrt-kit-tab-pill" aria-hidden="true"></span>
          ${SYSTEM_STARTUP_TABS.map((item) => `
            <button class="dwrt-kit-tab ${tab.id === item.id ? 'is-active' : ''}" type="button" role="tab" aria-selected="${tab.id === item.id ? 'true' : 'false'}" data-value="${escapeHtml(item.id)}" data-system-startup-tab="${escapeHtml(item.id)}">
              ${escapeHtml(item.label)}
            </button>
          `).join('')}
        </nav>
        ${error}${tab.id === 'local' ? systemStartupLocalPanel(startup) : systemStartupScriptsPanel(startup)}
      </div>
    `;
  }

  function systemStartupScriptsPanel(startup = {}) {
    const services = Array.isArray(startup.services) ? startup.services : [];
    return `
      <div class="system-startup-note">
        在此启用或禁用已安装的启动脚本，更改在设备重启后生效。警告：如果禁用了必要的启动脚本，比如 “network”，可能会导致无法访问设备！
      </div>
      <section class="dwrt-kit-table-wrap dwrt-kit-datatable-wrap dwrt-kit-glass-surface system-table-card system-startup-table-card">
        <div class="dwrt-kit-table-toolbar">
          <div class="dwrt-kit-table-title">
            <strong>启动脚本</strong>
            <span>/etc/init.d 服务列表，支持运行状态和自启动控制</span>
          </div>
          <span class="dwrt-kit-table-count">${formatInteger(services.length)} 个脚本</span>
        </div>
        <div class="dwrt-kit-table-scroll system-table-scroll" data-system-scroll="startup-services">
          <table class="dwrt-kit-table dwrt-kit-datatable system-startup-table-core" aria-label="启动脚本">
            <thead>
              <tr>
                <th scope="col" class="num">启动优先级</th>
                <th scope="col">启动脚本</th>
                <th scope="col">状态</th>
                <th scope="col">自启动</th>
                <th scope="col">操作</th>
              </tr>
            </thead>
            <tbody>
              ${services.length ? services.map((svc) => systemStartupServiceRow(svc)).join('') : `<tr><td colspan="5" class="dwrt-kit-table-empty">等待后端返回 /etc/init.d 启动脚本。</td></tr>`}
            </tbody>
          </table>
        </div>
      </section>
    `;
  }

  function systemStartupServiceRow(svc = {}) {
    const name = stringOr(svc.name || svc.service || svc.id || '-');
    const desc = stringOr(svc.desc || svc.description || '系统启动脚本');
    const running = Boolean(svc.running || svc.status === 'running' || svc.active === true);
    const enabled = svc.enabled !== false && svc.enable !== false && svc.autostart !== false;
    const priority = Number(svc.priority || svc.start || svc.order || 0);
    const workingPrefix = `startup:${name}:`;
    return `
      <tr>
        <td class="num" data-label="启动优先级">${formatInteger(priority)}</td>
        <td data-label="启动脚本">
          <span class="system-startup-script-name">
            <strong>${escapeHtml(name)}</strong>
            <em>${escapeHtml(desc)}</em>
          </span>
        </td>
        <td data-label="状态">${systemStatusBadge(running ? '运行中' : '已停止', running ? 'success' : 'error')}</td>
        <td data-label="自启动">${systemStatusBadge(enabled ? '已启用' : '已禁用', enabled ? 'info' : 'muted')}</td>
        <td data-label="操作">
          <div class="system-startup-actions">
            ${systemActionButton(enabled ? '禁用' : '启用', 'startup-service-toggle', name, state.operationWorking === `${workingPrefix}toggle`, enabled ? '' : 'primary')}
            ${running
              ? `${systemActionButton('重启', 'startup-service-restart', name, state.operationWorking === `${workingPrefix}restart`)}
                 ${systemActionButton('重新加载', 'startup-service-reload', name, state.operationWorking === `${workingPrefix}reload`)}
                 ${systemActionButton('停止', 'startup-service-stop', name, state.operationWorking === `${workingPrefix}stop`, 'danger')}`
              : systemActionButton('启动', 'startup-service-start', name, state.operationWorking === `${workingPrefix}start`, 'primary')}
          </div>
        </td>
      </tr>
    `;
  }

  function systemStatusBadge(label, tone = 'muted') {
    return ui.statusBadgeMarkup?.(label, tone) || `<span>${escapeHtml(label)}</span>`;
  }

  function systemActionButton(label, action, serviceName, disabled = false, tone = '') {
    return `<button class="system-demo-btn secondary compact-btn ${tone}" type="button" data-system-action="${escapeHtml(action)}" data-service-name="${escapeHtml(serviceName)}" ${disabled ? 'disabled' : ''}>${escapeHtml(disabled ? '处理中…' : label)}</button>`;
  }

  function systemStartupLocalPanel(startup = {}) {
    const script = systemStartupLocalText(startup);
    const lineCount = Math.max(8, script.split(/\r?\n/).length);
    return `
      <section class="system-demo-panel system-code-panel system-startup-local-panel">
        <div class="system-code-page-header">
          <div class="system-demo-panel-title">${systemSettingsIcon('terminal')}<span>本地启动脚本</span></div>
          <p>此处为 /etc/rc.local 的内容。将启动脚本插入到 “exit 0” 之前即可随系统启动运行。</p>
        </div>
        <div class="system-code-editor-container">
          <div class="system-code-line-numbers" aria-hidden="true">${Array.from({ length: lineCount }, (_, index) => `<div>${index + 1}</div>`).join('')}</div>
          <textarea class="system-code-editor" spellcheck="false" data-system-field="startup.local_script" data-system-scroll="startup-local-editor" data-system-scroll-sync="startup-local-editor">${escapeHtml(script)}</textarea>
        </div>
      </section>
    `;
  }

  function systemStartupLocalText(startup = {}) {
    if (typeof startup.local_script === 'string' && startup.local_script) return startup.local_script;
    return `# Put your custom commands here that should be executed once\n# the system init finished. By default this file does nothing.\n\nexit 0`;
  }

  function systemCrontabPanel(data) {
    const cronText = systemCronText(data.crontab || {});
    const lineCount = Math.max(8, cronText.split(/\r?\n/).length);
    const error = state.error ? `<div class="system-inline-error">${escapeHtml(state.error)}</div>` : '';
    return `
      <div class="system-page-workspace system-cron-workspace">
        ${error}
          <section class="system-demo-panel system-code-panel system-cron-panel">
            <div class="system-code-page-header">
              <div class="system-demo-panel-title">${systemSettingsIcon('clock')}<span>计划任务</span></div>
              <p>这是系统 crontab 文件，用于定义自动化定时任务。每行代表一个任务，格式为：分 时 日 月 周 <span class="system-cron-command-label">命令。</span></p>
            </div>
            <div class="system-code-editor-container">
              <div class="system-code-line-numbers" aria-hidden="true">${Array.from({ length: lineCount }, (_, index) => `<div>${index + 1}</div>`).join('')}</div>
              <textarea class="system-code-editor" spellcheck="false" data-system-field="crontab.text" data-system-scroll="crontab-editor" data-system-scroll-sync="crontab-editor">${escapeHtml(cronText)}</textarea>
            </div>
          </section>
      </div>
    `;
  }

  function systemCronText(crontab = {}) {
    if (typeof crontab.text === 'string' && crontab.text) return crontab.text;
    const jobs = Array.isArray(crontab.jobs) ? crontab.jobs : [];
    if (!jobs.length) return '';
    return jobs.map((job) => {
      const lines = [];
      if (job.desc || job.description) lines.push(`# ${job.desc || job.description}`);
      lines.push(`${job.enabled === false ? '# ' : ''}${job.schedule || '* * * * *'} ${job.command || ''}`.trim());
      return lines.join('\n');
    }).join('\n\n');
  }

  function systemMountsPanel(data) {
    const mounts = data.mounts || {};
    const points = Array.isArray(mounts.points) ? mounts.points : [];
    const mounted = dedupeMountPoints(points.filter((point) => String(point.status || '').toLowerCase() === 'mounted' || point.mounted === true));
    const configured = dedupeMountPoints(points);
    const error = state.error ? `<div class="system-inline-error">${escapeHtml(state.error)}</div>` : '';
    return `
      <div class="system-page-workspace system-mount-page">
        ${error}
          <section class="system-demo-panel system-mount-global">
            <div class="system-mount-global-copy">
              <div class="system-demo-panel-title">${systemSettingsIcon('disk')}<span>挂载点管理</span></div>
              <span>配置磁盘、分区及外部存储的挂载参数。</span>
            </div>
            <div class="system-mount-actions">
              <button class="system-demo-btn primary" type="button" data-system-action="mount-generate-config" ${state.operationWorking === 'mount:generate' ? 'disabled' : ''}>${state.operationWorking === 'mount:generate' ? '生成中…' : '生成配置'}</button>
              <button class="system-demo-btn secondary" type="button" data-system-action="mount-connected-devices" ${state.operationWorking === 'mount:connected' ? 'disabled' : ''}>${state.operationWorking === 'mount:connected' ? '挂载中…' : '挂载已连接设备'}</button>
            </div>
            <div class="system-mount-global-switches">
              ${systemMountToggle('自动挂载磁盘', 'mounts.auto_mount', mounts.auto_mount !== false)}
              ${systemMountToggle('自动挂载 SWAP 分区', 'mounts.auto_swap', Boolean(mounts.auto_swap))}
              ${systemMountToggle('挂载前检查文件系统', 'mounts.check_fs', Boolean(mounts.check_fs))}
            </div>
          </section>

          <section class="system-mount-section">
            <div class="system-mount-section-title">已挂载的文件系统</div>
            <div class="system-mount-grid">
              ${mounted.length ? mounted.map(systemMountedCard).join('') : `<div class="system-mount-empty">当前没有已挂载的外部文件系统。</div>`}
            </div>
          </section>

          <section class="dwrt-kit-table-wrap system-table-card system-mount-config-card">
            <div class="dwrt-kit-table-toolbar">
              <div class="dwrt-kit-table-title">
                <strong>挂载点与文件系统</strong>
                <span>查看设备来源、容量、文件系统类型及当前挂载位置</span>
              </div>
              <button class="system-demo-btn secondary compact-btn" type="button" data-system-action="mount-add">添加新挂载点</button>
            </div>
            <div class="dwrt-kit-table-scroll system-table-scroll" data-system-scroll="mount-config">
              <table class="dwrt-kit-table system-mount-table-core" aria-label="挂载点与文件系统">
                <thead><tr><th>设备</th><th>容量</th><th>文件系统</th><th>挂载点</th><th>状态</th><th>操作</th><th>启用</th></tr></thead>
                <tbody>${configured.length ? configured.map(systemMountConfigRow).join('') : `<tr><td colspan="7" class="dwrt-kit-table-empty">暂无挂载点配置。</td></tr>`}</tbody>
              </table>
            </div>
          </section>
      </div>
    `;
  }

  function systemMountToggle(label, field, checked) {
    return `
      <label class="system-mount-toggle-row">
        <span>${escapeHtml(label)}</span>
        ${systemIosSwitch(field, checked)}
      </label>
    `;
  }

  function systemMountedCard(point = {}) {
    const percent = clampPercent(point.used_percent ?? point.use_percent ?? point.usage_percent);
    const used = formatMountSize(point.used || point.used_size) || formatBytes(point.used_bytes);
    const available = formatMountSize(point.available || point.avail || point.free) || formatBytes(point.available_bytes || point.free_bytes);
    const device = point.device || point.id || point.uuid || '未知设备';
    const mount = point.mount || point.mount_point || point.target || '-';
    const fs = mountFilesystem(point);
    return `
      <article class="system-mount-card ${point.status && String(point.status).toLowerCase() !== 'mounted' ? 'is-muted' : ''}">
        <div class="system-mount-card-head">
          <span class="system-mount-fs">${escapeHtml(device)}</span>
          <span class="system-mount-point">${escapeHtml([fs || '文件系统待后端提供', `挂载至 ${mount}`].join(' · '))}</span>
        </div>
        <div class="system-mount-usage-info">
          <span>已使用 ${percent}%</span>
          <span>${escapeHtml(available ? `可用 ${available}` : (used ? `已用 ${used}` : (formatMountSize(point.size) ? `容量 ${formatMountSize(point.size)}` : '-')))}</span>
        </div>
        <div class="system-mount-progress"><i class="${percent >= 75 ? 'warn' : percent >= 45 ? 'ok' : ''}" style="width:${percent}%"></i></div>
        <div class="system-mount-card-actions">
          <button class="system-mount-text-danger" type="button" ${isSystemMount(point) ? 'disabled' : ''} data-system-action="mount-unmount" data-mount-id="${escapeHtml(mountActionId(point))}">${isSystemMount(point) ? '系统分区不可卸载' : '卸载分区'}</button>
        </div>
      </article>
    `;
  }

  function systemMountConfigRow(point = {}, index = 0) {
    const enabled = point.enabled !== false && point.status !== 'missing';
    const size = formatMountSize(point.size) || formatBytes(point.size_bytes);
    const device = point.device || point.source || '未知设备';
    const fs = mountFilesystem(point);
    const mount = point.mount || point.mount_point || point.target || '-';
    const status = point.status || (point.mounted ? 'mounted' : 'configured');
    const actionId = mountActionId(point);
    return `
      <tr class="${status === 'missing' ? 'is-muted' : ''}">
        <td><code class="system-mount-path">${escapeHtml(device)}</code></td>
        <td>${escapeHtml(size || '未知')}</td>
        <td>${fs ? escapeHtml(fs) : '<span class="system-mount-missing-meta">待后端提供</span>'}</td>
        <td><code class="system-mount-path">${escapeHtml(mount)}</code></td>
        <td>${systemStatusBadge(statusText(status), String(status).toLowerCase() === 'mounted' ? 'success' : 'muted')}</td>
        <td>
          <div class="system-mount-row-actions">
            <button type="button" title="编辑" data-system-action="mount-edit" data-mount-id="${escapeHtml(actionId)}">${systemSettingsIcon('edit')}</button>
            <button class="danger" type="button" title="删除" data-system-action="mount-delete" data-mount-id="${escapeHtml(actionId)}">${systemSettingsIcon('delete')}</button>
          </div>
        </td>
        <td class="system-mount-enabled-cell">${systemIosSwitch(`mounts.points.${index}.enabled`, enabled)}</td>
      </tr>
    `;
  }

  function mountActionId(point = {}) {
    return stringOr(point.id || point.uuid || point.device || point.mount || point.mount_point || point.target);
  }

  function mountFilesystem(point = {}) {
    return stringOr(point.fs || point.fstype || point.filesystem || point.filesystem_type);
  }

  function dedupeMountPoints(points = []) {
    const seen = new Set();
    const out = [];
    (Array.isArray(points) ? points : []).forEach((point) => {
      const key = [
        point.uuid || '',
        point.device || point.source || '',
        point.mount || point.mount_point || point.target || '',
        mountFilesystem(point)
      ].map((item) => String(item || '').trim()).join('|');
      if (seen.has(key)) return;
      seen.add(key);
      out.push(point);
    });
    return out;
  }

  function formatMountSize(value) {
    if (value === undefined || value === null || value === '') return '';
    const text = String(value).trim();
    if (!text) return '';
    if (/[a-zA-Z]/.test(text)) return text;
    const n = Number(text);
    if (!Number.isFinite(n) || n <= 0) return text;
    return formatBytes(n * 1024);
  }

  function statusText(status) {
    const s = String(status || '').toLowerCase();
    if (s === 'mounted') return '已挂载';
    if (s === 'missing') return '缺失';
    if (s === 'error') return '错误';
    return '已配置';
  }

  function clampPercent(value) {
    const n = Number(value || 0);
    return Math.max(0, Math.min(100, Math.round(n * 10) / 10));
  }

  function isSystemMount(point = {}) {
    const mount = String(point.mount || point.mount_point || point.target || '');
    return mount === '/' || mount === '/overlay' || mount === '/rom' || point.system === true;
  }

  function systemAdminPanel(data) {
    const admin = data.admin || {};
    const ssh = data.ssh || {};
    const twofa = data.twofa || {};
    const apiData = data.api || {};
    const avatarUrl = admin.avatar_url || '';
    const avatarCandidate = admin.avatar_preview_url || avatarUrl;
    const avatarPreview = admin.avatar_broken_url && admin.avatar_broken_url === avatarCandidate ? '' : avatarCandidate;
    const webTimeoutSupported = data.capabilities?.web_login_timeout === true;
    const error = state.error ? `<div class="system-inline-error">${escapeHtml(state.error)}</div>` : '';
    return `
      <div class="system-admin-workspace">
        ${error}
        <div class="system-admin-chambers">
          <section class="system-demo-panel system-admin-chamber system-admin-account-chamber">
            <div class="system-demo-panel-title system-admin-chamber-title">${systemSettingsIcon('identity')}<span>管理员账户设置</span></div>
            <div class="system-admin-account-body">
              <div class="system-admin-avatar-card">
                <span class="system-admin-avatar-preview" aria-hidden="true">
                  ${avatarPreview ? `<img src="${escapeHtml(avatarPreview)}" alt="" data-system-avatar-img>` : systemSettingsIcon('identity')}
                </span>
                <div class="system-admin-input-group">
                  <span>用户头像</span>
                  <div class="system-admin-avatar-actions">
                    <label class="system-admin-upload-btn ${state.avatarWorking ? 'is-working' : ''}">
                      <input type="file" accept="image/png,image/jpeg,image/webp" data-system-avatar-upload ${state.avatarWorking ? 'disabled' : ''}>
                      <span>${systemSettingsIcon('upload')}${state.avatarWorking ? '正在上传' : '从浏览器上传'}</span>
                    </label>
                    <em class="${admin.avatar_upload_error ? 'error' : ''}">${escapeHtml(admin.avatar_upload_error || admin.avatar_filename || '选择后立即生效，支持 PNG / JPG / WebP')}</em>
                  </div>
                </div>
              </div>
              <div class="system-admin-account-meta-grid">
                <label class="system-admin-input-group system-admin-account-username">
                  <span>登录用户名</span>
                  ${systemInputControl('admin.username', admin.username || 'root', 'text', '设置新的用户名')}
                </label>
                <label class="system-admin-input-group">
                  <span>Web 登录超时</span>
                  <div class="system-admin-unit-field">
                    <input class="system-glass-input" type="number" min="1" max="1440" value="${escapeHtml(admin.web_login_timeout_min || 60)}" data-system-field="admin.web_login_timeout_min" ${webTimeoutSupported ? '' : 'disabled'}>
                    <em>MINS</em>
                  </div>
                  ${webTimeoutSupported ? '' : '<small class="system-admin-capability-note">后端待接入</small>'}
                </label>
              </div>
              <div class="system-admin-password-grid">
                <label class="system-admin-input-group">
                  <span>新登录密码</span>
                  ${systemInputControl('admin.new_password', admin.new_password || '', 'password', '••••••••')}
                </label>
                <label class="system-admin-input-group">
                  <span>确认新密码</span>
                  ${systemInputControl('admin.confirm_password', admin.confirm_password || '', 'password', '••••••••')}
                </label>
              </div>
            </div>
          </section>
          <section class="system-demo-panel system-admin-chamber system-admin-ssh-chamber">
            <div class="system-demo-panel-title system-admin-chamber-title">${systemSettingsIcon('key')}<span>SSH 访问控制</span></div>
            <div class="system-admin-ssh-quick-grid">
              ${systemAdminHeroCard('启用 SSH 服务', '允许通过命令行终端管理路由器', 'ssh.enabled', ssh.enabled !== false)}
              <label class="system-admin-input-group">
                <span>监听端口</span>
                <div class="system-admin-unit-field">
                  ${systemInputControl('ssh.port', ssh.port || 22, 'number')}
                  <em>PORT</em>
                </div>
              </label>
              <label class="system-admin-input-group">
                <span>空闲超时</span>
                <div class="system-admin-unit-field">
                  ${systemInputControl('ssh.idle_timeout_min', ssh.idle_timeout_min ?? 30, 'number')}
                  <em>MINS</em>
                </div>
              </label>
            </div>
            <div class="system-admin-policy-list">
              ${systemAdminPolicyTile('允许密码登录', 'ssh.password_login', ssh.password_login !== false)}
              ${systemAdminPolicyTile('允许 Root 密码登录', 'ssh.root_password_login', ssh.root_password_login !== false)}
              ${systemAdminPolicyTile('仅限密钥登录 (Public Key)', 'ssh.key_only', Boolean(ssh.key_only))}
            </div>
          </section>
        </div>
        <div class="system-admin-security-grid">
          ${systemTwofaPanel(twofa)}
          ${systemAppPairingPanel(apiData)}
        </div>
      </div>
    `;
  }

  function systemAdminHeroCard(label, hint, field, checked) {
    return `
      <label class="system-admin-hero-card">
        <input type="checkbox" ${checked ? 'checked' : ''} data-system-field="${escapeHtml(field)}">
        <span class="system-admin-hero-copy"><strong>${escapeHtml(label)}</strong><em>${escapeHtml(hint)}</em></span>
        <span class="system-admin-master-switch" aria-hidden="true"><i></i></span>
      </label>
    `;
  }

  function systemAdminPolicyTile(label, field, checked) {
    return `
      <div class="system-admin-policy-tile">
        <span>${escapeHtml(label)}</span>
        ${systemIosSwitch(field, checked)}
      </div>
    `;
  }

  function systemTwofaPanel(twofa = {}) {
    const enabled = Boolean(twofa.twofa_enabled || twofa.enabled);
    const hasPrepared = Boolean(twofa.secret || twofa.otpauth_url);
    const meta = `${Number(twofa.digits || 6)} 位 · ${Number(twofa.period || 30)} 秒刷新 · ${escapeHtml(twofa.method || 'totp').toUpperCase()}`;
    return `
      <section class="system-demo-panel system-admin-otp-panel">
        <div class="system-demo-panel-title">${systemSettingsIcon('shield')}<span>OTP 验证码绑定</span></div>
        <div class="system-admin-status-row">
          <span class="system-admin-status-light ${enabled ? 'ok' : ''}" aria-hidden="true">${systemSettingsIcon('key')}</span>
          <div>
            <strong>${enabled ? '已启用双因素验证' : (hasPrepared ? '已生成绑定密钥，等待验证' : '未绑定双因素验证')}</strong>
            <em>${escapeHtml(meta)}</em>
          </div>
          <button class="system-demo-btn ${enabled ? 'secondary' : 'primary'}" type="button" data-system-action="twofa-open-binding" ${state.twofaWorking ? 'disabled' : ''}>${enabled ? '管理绑定' : '准备绑定'}</button>
        </div>
        <p class="system-admin-security-note">${enabled ? '登录时需要验证器生成的动态验证码。解绑也会在小窗口中再次验证。' : '扫描二维码并输入动态验证码，请妥善保管密钥。'}</p>
      </section>
    `;
  }

  function systemAppPairingPanel(apiData = {}) {
    const devices = Array.isArray(apiData.paired_devices) ? apiData.paired_devices : [];
    const pairedDevices = devices.filter((device) => Number(device?.paired_at || 0) > 0 || String(device?.state || '') === 'paired');
    return `
      <section class="system-demo-panel system-admin-app-panel">
        <div class="system-demo-panel-title">${systemSettingsIcon('phone')}<span>App 配对</span></div>
        <div class="system-admin-status-row system-admin-app-status">
          <span class="system-admin-status-light ${pairedDevices.length ? 'ok' : ''}" aria-hidden="true">${systemSettingsIcon('phone')}</span>
          <div>
            <strong>${pairedDevices.length} 台 App 已绑定</strong>
          </div>
          <button class="system-demo-btn primary" type="button" data-system-action="api-open-pairing" ${state.pairWorking ? 'disabled' : ''}>准备绑定</button>
        </div>
        <div class="system-api-device-list">
          <div class="system-admin-list-head"><strong>已绑定 App</strong><span>${pairedDevices.length} 台设备</span></div>
          ${pairedDevices.length ? pairedDevices.map(systemApiDeviceRow).join('') : `<div class="system-api-empty">还没有已绑定 App。</div>`}
        </div>
      </section>
    `;
  }

  function systemBindingDialog() {
    if (page !== 'admin' || !state.bindingDialog) return '';
    return state.bindingDialog === 'otp' ? systemOtpBindingDialog() : systemAppBindingDialog();
  }

  function systemOtpBindingDialog() {
    const twofa = state.data.twofa || {};
    const enabled = Boolean(twofa.twofa_enabled || twofa.enabled);
    const prepared = Boolean(twofa.secret || twofa.otpauth_url);
    const qr = safeQrSvg(twofa.qr_svg);
    return `
      <div class="dwrt-kit-modal-layer system-binding-layer is-open" data-system-dialog="otp">
        <button class="dwrt-kit-modal-backdrop" type="button" aria-label="关闭 OTP 绑定窗口" data-system-action="binding-close"></button>
        <section class="dwrt-kit-modal system-binding-dialog" role="dialog" aria-modal="true" aria-labelledby="systemOtpDialogTitle">
          <header class="dwrt-kit-modal-header">
            <div>
              <h2 id="systemOtpDialogTitle">${enabled ? '管理 OTP 验证' : '绑定 OTP 验证器'}</h2>
              <p>${enabled ? '验证当前动态验证码后可以解除绑定。' : '扫描二维码后输入验证器显示的 6 位动态验证码。'}</p>
            </div>
            <button class="dwrt-kit-modal-close" type="button" aria-label="关闭" data-system-action="binding-close">${systemSettingsIcon('close')}</button>
          </header>
          <div class="dwrt-kit-modal-body system-binding-body">
            ${enabled ? `
              <div class="system-binding-state is-success">${systemSettingsIcon('shield')}<span><strong>双因素验证已启用</strong><em>${Number(twofa.digits || 6)} 位验证码 · ${Number(twofa.period || 30)} 秒刷新</em></span></div>
              <label class="system-binding-code-field"><span>当前验证码</span>${systemBindingCodeInput('twofa.disable_code', twofa.disable_code || '', '输入 6 位验证码')}</label>
            ` : !prepared ? `
              <div class="system-binding-loading" role="status">${systemSettingsIcon('sync')}<span>${state.twofaWorking ? '正在准备安全密钥…' : '尚未生成绑定信息'}</span></div>
            ` : `
              <div class="system-binding-qr-grid">
                <div class="system-binding-qr" aria-label="OTP 绑定二维码">${qr || `<div class="system-binding-qr-unavailable">${systemSettingsIcon('warning')}<span>二维码暂不可用</span></div>`}</div>
                <div class="system-binding-instructions">
                  <ol><li>在验证器 App 中选择添加账户</li><li>扫描左侧二维码，或输入下方密钥</li><li>输入 App 生成的动态验证码</li></ol>
                  <div class="system-binding-secret"><span>手动密钥</span><strong>${escapeHtml(twofa.secret || '')}</strong></div>
                </div>
              </div>
              <label class="system-binding-code-field"><span>动态验证码</span>${systemBindingCodeInput('twofa.code', twofa.code || '', '输入 6 位验证码')}</label>
            `}
          </div>
          <footer class="dwrt-kit-modal-footer">
            <button class="system-demo-btn secondary" type="button" data-system-action="binding-close">取消</button>
            ${enabled
              ? `<button class="system-demo-btn secondary danger" type="button" data-system-action="twofa-disable" ${state.twofaWorking ? 'disabled' : ''}>${state.twofaWorking ? '验证中…' : '验证并解绑'}</button>`
              : `<button class="system-demo-btn primary" type="button" data-system-action="twofa-enable" ${(!prepared || !String(twofa.code || '').trim() || state.twofaWorking) ? 'disabled' : ''}>${state.twofaWorking ? '验证中…' : '验证并启用'}</button>`}
          </footer>
        </section>
      </div>`;
  }

  function systemAppBindingDialog() {
    const pairState = state.pairState || 'waiting';
    const candidate = state.pairCandidate || null;
    const qrPayload = appPairQrPayload();
    const qr = appPairQrMarkup(qrPayload);
    return `
      <div class="dwrt-kit-modal-layer system-binding-layer is-open" data-system-dialog="app">
        <button class="dwrt-kit-modal-backdrop" type="button" aria-label="关闭 App 配对窗口" data-system-action="binding-close"></button>
        <section class="dwrt-kit-modal system-binding-dialog" role="dialog" aria-modal="true" aria-labelledby="systemAppDialogTitle">
          <header class="dwrt-kit-modal-header">
            <div>
              <h2 id="systemAppDialogTitle">App 配对</h2>
              <p>让 App 扫描二维码，并由 App 使用自身设备身份发起配对。</p>
            </div>
            <button class="dwrt-kit-modal-close" type="button" aria-label="关闭" data-system-action="binding-close">${systemSettingsIcon('close')}</button>
          </header>
          <div class="dwrt-kit-modal-body system-binding-body">
            ${pairState === 'paired' ? `
              <div class="system-binding-complete">${systemSettingsIcon('shield')}<strong>App 已完成配对</strong><span>设备列表已刷新，可以关闭此窗口。</span></div>
            ` : `
              <div class="system-binding-qr-grid">
                <div class="system-binding-qr" aria-label="App 配对二维码">${qr}</div>
                <div class="system-pair-code-block">
                  <span>${pairState === 'requested' ? 'App 已发起配对' : '等待 App 扫描'}</span>
                  <strong class="system-pair-device-name">${escapeHtml(pairState === 'requested' ? (candidate?.name || candidate?.id || '待确认设备') : '扫描二维码')}</strong>
                  <em data-system-pair-countdown>${pairState === 'requested' && candidate?.expires_at ? `${pairingRemainingSeconds(candidate)} 秒后过期` : '请在 Dreaming OS App 中继续'}</em>
                  <p>${pairState === 'requested' ? '配对码由 App 获取并确认；此窗口正在等待真实设备状态变为 paired。' : `二维码包含路由器地址 <b>${escapeHtml(appPairBaseUrl())}</b> 和真实 App 配对端点。`}</p>
                </div>
              </div>
              ${state.qrGeneratorError ? `<div class="system-binding-warning">${escapeHtml(state.qrGeneratorError)}，仍可使用 6 位配对码。</div>` : ''}
            `}
          </div>
          <footer class="dwrt-kit-modal-footer">
            ${candidate && pairState === 'requested' ? `<button class="system-demo-btn primary" type="button" data-system-action="api-approve-pairing" ${state.pairWorking ? 'disabled' : ''}>${state.pairWorking ? '处理中…' : '批准这台设备'}</button>` : ''}
            ${candidate && pairState === 'requested' ? `<button class="system-demo-btn secondary danger" type="button" data-system-action="api-cancel-pairing" ${state.pairWorking ? 'disabled' : ''}>拒绝 / 取消</button>` : ''}
            <button class="system-demo-btn ${pairState === 'paired' ? 'primary' : 'secondary'}" type="button" data-system-action="binding-close">${pairState === 'paired' ? '完成' : '关闭'}</button>
          </footer>
        </section>
      </div>`;
  }

  function systemBindingCodeInput(field, value, placeholder) {
    return `<input class="system-glass-input system-binding-code-input" type="text" inputmode="numeric" autocomplete="one-time-code" maxlength="6" pattern="[0-9]{6}" value="${escapeHtml(value)}" placeholder="${escapeHtml(placeholder)}" data-system-field="${escapeHtml(field)}" autofocus>`;
  }

  function safeQrSvg(value) {
    const raw = String(value || '').trim();
    if (!/<svg\b/i.test(raw) || !/<\/svg>/i.test(raw)) return '';
    try {
      const doc = new DOMParser().parseFromString(raw, 'image/svg+xml');
      const svg = doc.documentElement;
      if (!svg || svg.localName !== 'svg' || doc.querySelector('parsererror')) return '';
      if (svg.querySelector('script, foreignObject, iframe, object, embed, image, use, style')) return '';
      for (const element of svg.querySelectorAll('*')) {
        for (const attribute of Array.from(element.attributes)) {
          const name = attribute.name.toLowerCase();
          const text = String(attribute.value || '').trim().toLowerCase();
          if (name.startsWith('on') || name === 'href' || name.endsWith(':href') || text.includes('javascript:') || text.includes('url(')) {
            return '';
          }
        }
      }
      svg.removeAttribute('width');
      svg.removeAttribute('height');
      svg.setAttribute('role', 'img');
      svg.setAttribute('aria-label', 'OTP 绑定二维码');
      return new XMLSerializer().serializeToString(svg);
    } catch (_) {
      return '';
    }
  }

  function appPairBaseUrl() {
    return `${window.location.protocol}//${window.location.host}`;
  }

  function appPairQrPayload() {
    return JSON.stringify({
      type: 'dreamingwrt-app-pairing',
      version: 1,
      base_url: appPairBaseUrl(),
      init_path: '/api/v1/auth/pair/init',
      confirm_path: '/api/v1/auth/pair/confirm',
      status_path: '/api/v1/auth/pair/status'
    });
  }

  function appPairQrMarkup(payload) {
    if (!payload) return `<div class="system-binding-qr-unavailable">${systemSettingsIcon('warning')}<span>二维码暂不可用</span></div>`;
    if (typeof window.qrcode !== 'function') {
      ensureQrGenerator();
      return `<div class="system-binding-qr-unavailable">${systemSettingsIcon('sync')}<span>${state.qrGeneratorError ? '二维码暂不可用' : '正在生成二维码…'}</span></div>`;
    }
    try {
      const qr = window.qrcode(0, 'M');
      qr.addData(payload, 'Byte');
      qr.make();
      return qr.createSvgTag({ cellSize: 5, margin: 0, scalable: true });
    } catch (error) {
      state.qrGeneratorError = error?.message || '二维码生成失败';
      return `<div class="system-binding-qr-unavailable">${systemSettingsIcon('warning')}<span>二维码暂不可用</span></div>`;
    }
  }

  function ensureQrGenerator() {
    if (typeof window.qrcode === 'function' || state.qrGeneratorLoading) return;
    state.qrGeneratorLoading = true;
    state.qrGeneratorError = '';
    const existing = document.querySelector('script[data-dwrt-qrcode-generator]');
    const script = existing || document.createElement('script');
    script.dataset.dwrtQrcodeGenerator = 'true';
    script.src = `/static/vendor/qrcode-generator.min.js?v=${encodeURIComponent(VERSION)}`;
    script.async = true;
    script.addEventListener('load', () => {
      state.qrGeneratorLoading = false;
      if (typeof window.qrcode !== 'function') state.qrGeneratorError = '二维码组件未加载';
      if (state.mounted && state.bindingDialog === 'app') render();
    }, { once: true });
    script.addEventListener('error', () => {
      state.qrGeneratorLoading = false;
      state.qrGeneratorError = '二维码组件加载失败';
      if (state.mounted && state.bindingDialog === 'app') render();
    }, { once: true });
    if (!existing) document.head.append(script);
  }

  function pairingRemainingSeconds(pairing = {}) {
    const expiresAt = Number(pairing.expires_at || 0);
    if (expiresAt > 0) return Math.max(0, expiresAt - Math.floor(Date.now() / 1000));
    return Math.max(0, Number(pairing.expires_in || 0));
  }

  function focusBindingDialog() {
    requestAnimationFrame(() => requestAnimationFrame(() => {
      const dialog = root?.querySelector('.system-binding-dialog');
      const target = dialog?.querySelector('[autofocus], input:not(:disabled), button:not(:disabled)');
      if (target instanceof HTMLElement && !dialog.contains(document.activeElement)) {
        try { target.focus({ preventScroll: true }); } catch (_) { target.focus(); }
      }
    }));
  }

  function openBindingDialog(kind) {
    state.bindingDialog = kind === 'app' ? 'app' : 'otp';
    state.saveError = '';
    if (state.bindingDialog === 'otp') {
      render();
      const twofa = state.data.twofa || {};
      if (!twofa.twofa_enabled && !twofa.enabled && !twofa.secret && !twofa.otpauth_url) prepareTwofa();
      return;
    }
    const devices = Array.isArray((state.data.api || {}).paired_devices) ? state.data.api.paired_devices : [];
    state.pairBaselineIds = devices.map(appDeviceId).filter(Boolean);
    state.pairCandidate = null;
    state.pairState = 'waiting';
    ensureQrGenerator();
    render();
    startPairStatusTimer();
  }

  function closeBindingDialog() {
    const layer = root?.querySelector('.system-binding-layer');
    const returnSelector = layer?.dataset.dwrtReturnFocus || '';
    state.bindingDialog = '';
    stopPairStatusTimer();
    render();
    if (returnSelector) requestAnimationFrame(() => {
      const target = document.querySelector(returnSelector);
      if (target instanceof HTMLElement) target.focus({ preventScroll: true });
    });
  }

  function onBindingDialogKeydown(event) {
    if (event.key === 'Escape' && state.bindingDialog) {
      event.preventDefault();
      closeBindingDialog();
    }
  }

  function stopPairStatusTimer() {
    if (state.pairTimer) window.clearInterval(state.pairTimer);
    state.pairTimer = 0;
    state.pairPollTicks = 0;
  }

  function startPairStatusTimer() {
    stopPairStatusTimer();
    if (!state.mounted || state.bindingDialog !== 'app' || state.pairState === 'paired') return;
    pollPairingProgress();
    state.pairTimer = window.setInterval(() => {
      if (!state.mounted || state.bindingDialog !== 'app') {
        stopPairStatusTimer();
        return;
      }
      if (state.pairCandidate) {
        const remaining = pairingRemainingSeconds(state.pairCandidate);
        root?.querySelector('[data-system-pair-countdown]')?.replaceChildren(document.createTextNode(`${remaining} 秒后过期`));
        if (remaining <= 0 && state.pairState === 'requested') {
          const id = appDeviceId(state.pairCandidate);
          if (id && !state.pairBaselineIds.includes(id)) state.pairBaselineIds.push(id);
          state.pairCandidate = null;
          state.pairState = 'waiting';
          render();
        }
      }
      state.pairPollTicks += 1;
      if (state.pairPollTicks % 2 === 0) pollPairingProgress();
    }, 1000);
  }

  function appDeviceId(device = {}) {
    return String(device.id || device.device_id || device.pair_id || '');
  }

  function appDevicePending(device = {}) {
    const expiresAt = Number(device.expires_at || device.pair_expires_at || 0);
    return String(device.state || '').toLowerCase() === 'pending'
      || (Number(device.paired_at || 0) <= 0 && expiresAt > Math.floor(Date.now() / 1000));
  }

  async function pollPairingProgress() {
    if (state.pairPollBusy || state.pairState === 'paired' || state.bindingDialog !== 'app') return;
    state.pairPollBusy = true;
    try {
      const result = await fetchJson('/api/v1/auth/devices');
      const payload = result?.data && typeof result.data === 'object' ? result.data : result;
      const devices = Array.isArray(payload?.devices) ? payload.devices : [];
      state.data = mergeSystemSettingsValue(state.data, { api: { paired_devices: devices } });
      const candidate = state.pairCandidate
        ? devices.find((device) => appDeviceId(device) === appDeviceId(state.pairCandidate))
        : devices.find((device) => {
            const id = appDeviceId(device);
            return id && !state.pairBaselineIds.includes(id) && (appDevicePending(device) || Number(device.paired_at || 0) > 0);
          });
      if (!candidate) return;
      state.pairCandidate = candidate;
      if (Number(candidate.paired_at || 0) > 0 || String(candidate.state || '') === 'paired') {
        state.pairState = 'paired';
        stopPairStatusTimer();
      } else {
        state.pairState = 'requested';
      }
      if (state.mounted && state.bindingDialog === 'app') render();
    } catch (error) {
      state.saveError = error?.message || '配对状态不可用';
      refreshSavebarOnly();
    } finally {
      state.pairPollBusy = false;
    }
  }

  function systemApiDeviceRow(device = {}) {
    const id = device.id || device.device_id || '';
    const enabled = device.enabled !== false && device.state !== 'disabled';
    const lastSeen = Number(device.last_seen || 0);
    const pairedAt = Number(device.paired_at || 0);
    return `
      <article class="system-api-row ${enabled ? '' : 'disabled'}">
        <span class="system-api-row-icon" aria-hidden="true">${systemSettingsIcon(device.platform === 'android' ? 'android' : 'phone')}</span>
        <span>
          <strong>${escapeHtml(device.name || 'App Device')}</strong>
          <em>${escapeHtml([device.platform, device.role, lastSeen ? `上次 ${relativeSeconds(lastSeen)}` : '', pairedAt ? `绑定 ${relativeSeconds(pairedAt)}` : ''].filter(Boolean).join(' · ') || id || '等待后端返回设备信息')}</em>
        </span>
        <b class="${enabled ? 'good' : ''}">${enabled ? '启用' : '停用'}</b>
        <button class="system-demo-btn secondary compact-btn" type="button" data-system-action="api-revoke-device" data-api-id="${escapeHtml(id)}" ${!id || state.deviceWorking === id ? 'disabled' : ''}>撤销</button>
      </article>
    `;
  }

  function systemSettingsRow(label, content, align = 'center', extraClass = '') {
    return `
      <div class="system-demo-row ${align === 'top' ? 'top' : ''} ${escapeHtml(extraClass)}">
        <div class="system-demo-label">${escapeHtml(label)}</div>
        <div class="system-demo-control">${content}</div>
      </div>
    `;
  }

  function systemInputControl(field, value, type = 'text', placeholder = '') {
    return `<input class="system-glass-input" type="${escapeHtml(type)}" value="${escapeHtml(value ?? '')}" placeholder="${escapeHtml(placeholder)}" data-system-field="${escapeHtml(field)}">`;
  }

  function systemTextareaControl(field, value, placeholder = '') {
    return `<textarea class="system-glass-input" placeholder="${escapeHtml(placeholder)}" data-system-field="${escapeHtml(field)}">${escapeHtml(value ?? '')}</textarea>`;
  }

  function systemSelectControl(field, current, options, extraClass = '') {
    return `<select class="system-glass-input ${escapeHtml(extraClass)}" data-native-select="true" data-system-field="${escapeHtml(field)}">${options.map(([value, text]) => `<option value="${escapeHtml(value)}" ${String(current) === String(value) ? 'selected' : ''}>${escapeHtml(text)}</option>`).join('')}</select>`;
  }

  function systemLogLevelOptions() {
    return [
      ['emergency', '紧急（Emergency）'],
      ['alert', '警报（Alert）'],
      ['critical', '严重（Critical）'],
      ['error', '错误（Error）'],
      ['warning', '警告（Warning）'],
      ['notice', '通知（Notice）'],
      ['info', '信息（Info）'],
      ['debug', '调试（Debug）']
    ];
  }

  function systemLevelBadge(level) {
    const normalized = String(level || 'warning').toLowerCase();
    const label = {
      emergency: '紧急',
      alert: '警报',
      critical: '严重',
      error: '错误',
      warning: '警告',
      notice: '通知',
      info: '信息',
      debug: '调试'
    }[normalized] || '警告';
    const tone = ['emergency', 'alert', 'critical', 'error'].includes(normalized) ? 'danger' : (normalized === 'warning' ? 'warning' : 'info');
    return `<span class="system-level-badge ${tone}">${escapeHtml(label)}</span>`;
  }

  function systemSegmentedControl(field, current, options) {
    return `
      <div class="system-segmented-control" role="group">
        ${options.map(([value, text]) => `<button class="system-segment-btn ${String(current) === String(value) ? 'active' : ''}" type="button" data-system-segment="${escapeHtml(field)}" data-system-value="${escapeHtml(value)}">${escapeHtml(text)}</button>`).join('')}
      </div>
    `;
  }

  function systemIosSwitch(field, checked) {
    return `
      <label class="system-ios-switch dwrt-switch ${checked ? 'on' : ''}">
        <input type="checkbox" ${checked ? 'checked' : ''} data-system-field="${escapeHtml(field)}">
        <span class="dwrt-slider" aria-hidden="true"></span>
      </label>
    `;
  }

  function systemSettingsItem(label, control) {
    return `
      <div class="system-settings-item">
        <div class="system-settings-label">${escapeHtml(label)}</div>
        <div class="system-settings-control">${control}</div>
      </div>
    `;
  }

  function systemServerItem(index, server) {
    return `
      <div class="system-server-item">
        <button class="system-circle-btn remove" type="button" data-system-action="ntp-remove" data-ntp-index="${index}">-</button>
        <input class="system-glass-input" type="text" value="${escapeHtml(server || '')}" placeholder="例如：pool.ntp.org" data-system-ntp-index="${index}">
      </div>
    `;
  }

  function systemPreferenceItem(icon, label, control) {
    return `
      <div class="system-preference-item">
        <div class="system-preference-info">
          <span class="system-icon-circle" aria-hidden="true">${systemSettingsIcon(icon)}</span>
          <span>${escapeHtml(label)}</span>
        </div>
        <div class="system-preference-control">${control}</div>
      </div>
    `;
  }

  function systemZramItem(label, hint, control) {
    return `
      <div class="system-zram-item">
        <div class="system-zram-label">
          <span>${escapeHtml(label)}</span>
          <em>${escapeHtml(hint)}</em>
        </div>
        <div class="system-zram-control">${control}</div>
      </div>
    `;
  }

  function systemTimezoneOptions() {
    return [
      ['Asia/Shanghai', 'Asia/Shanghai'],
      ['Asia/Hong_Kong', 'Asia/Hong_Kong'],
      ['Asia/Tokyo', 'Asia/Tokyo'],
      ['UTC', 'UTC'],
      ['Europe/London', 'Europe/London'],
      ['America/New_York', 'America/New_York'],
      ['America/Los_Angeles', 'America/Los_Angeles']
    ];
  }

  function systemLocalTimeText(g = {}) {
    const date = new Date();
    const use12 = g.time_format === '12h';
    const options = {
      year: 'numeric',
      month: 'long',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
      hour12: use12,
      timeZoneName: g.show_timezone_name === false ? 'shortOffset' : 'short'
    };
    if (g.timezone) options.timeZone = g.timezone;
    try { return new Intl.DateTimeFormat('zh-CN', options).format(date); }
    catch (_) {
      delete options.timeZone;
      return new Intl.DateTimeFormat('zh-CN', options).format(date);
    }
  }

  function systemSettingsSavebar() {
    const isDirty = dirty();
    const error = state.saveError;
    const savedAt = Number(state.savedAt || 0);
    let text = '配置已修改，请保存生效';
    if (state.saving) text = '正在保存系统设置…';
    else if (error) text = `保存失败：${error}`;
    else if (!isDirty && savedAt) text = `已保存 ${relativeSeconds(savedAt)}`;
    return ui.floatingSavebarMarkup?.({
      visible: isDirty || state.saving || Boolean(error),
      message: text,
      busy: state.saving,
      disabled: !isDirty,
      discardLabel: '撤销更改',
      saveLabel: '保存并应用'
    }) || '';
  }

  function relativeSeconds(ts) {
    const diff = Math.max(0, Math.floor(Date.now() / 1000) - Number(ts || 0));
    if (diff < 3) return '刚刚';
    if (diff < 60) return `${diff} 秒前`;
    if (diff < 3600) return `${Math.floor(diff / 60)} 分钟前`;
    return `${Math.floor(diff / 3600)} 小时前`;
  }

  function updateClockText() {
    if (!root || !state.mounted) return;
    const node = root.querySelector('[data-system-clock]');
    if (!node) return;
    node.textContent = systemLocalTimeText(state.data.general || {});
  }

  function bindCurrentFields() {
    root.querySelectorAll('[data-system-field]').forEach((el) => {
      el.addEventListener('input', onFieldInput);
      el.addEventListener('change', onFieldChange);
    });
    root.querySelectorAll('[data-system-ntp-index]').forEach((el) => {
      el.addEventListener('input', onNtpInput);
      el.addEventListener('change', onNtpInput);
    });
    root.querySelectorAll('[data-system-avatar-upload]').forEach((el) => {
      el.addEventListener('change', onAvatarUpload);
    });
    root.querySelectorAll('[data-system-avatar-img]').forEach((el) => {
      el.addEventListener('error', onAvatarImageError, { once: true });
    });
    root.querySelectorAll('[data-system-scroll-sync]').forEach((el) => {
      el.addEventListener('scroll', onCodeScroll, { passive: true });
    });
    root.querySelectorAll('[data-system-flash-file]').forEach((el) => {
      el.addEventListener('change', onFlashFileSelect);
    });
    root.querySelectorAll('[data-system-flash-preserve]').forEach((el) => {
      el.addEventListener('input', onFlashPreserveInput);
    });
    root.querySelectorAll('[data-system-flash-keep-settings]').forEach((el) => {
      el.addEventListener('change', onFlashKeepSettingsChange);
    });
    root.querySelectorAll('[data-system-signature-upload]').forEach((el) => {
      el.addEventListener('change', onSignatureUpdateFileSelect);
    });
  }

  function captureSystemFocus() {
    const active = document.activeElement;
    if (!(active instanceof HTMLElement) || !root?.contains(active)) return null;
    let selector = '';
    if (active.dataset.systemField) selector = `[data-system-field="${cssEscape(active.dataset.systemField)}"]`;
    else if (active.dataset.systemNtpIndex !== undefined) selector = `[data-system-ntp-index="${cssEscape(active.dataset.systemNtpIndex)}"]`;
    else if (active.dataset.systemFlashPreserve !== undefined) selector = '[data-system-flash-preserve]';
    if (!selector) return null;
    return {
      selector,
      start: typeof active.selectionStart === 'number' ? active.selectionStart : null,
      end: typeof active.selectionEnd === 'number' ? active.selectionEnd : null
    };
  }

  function restoreSystemFocus(snapshot) {
    if (!snapshot?.selector) return;
    const next = root.querySelector(snapshot.selector);
    if (!(next instanceof HTMLElement)) return;
    try { next.focus({ preventScroll: true }); } catch (_) { next.focus(); }
    if (snapshot.start !== null && typeof next.setSelectionRange === 'function') {
      try { next.setSelectionRange(snapshot.start, snapshot.end ?? snapshot.start); } catch (_) {}
    }
  }

  function onFlashFileSelect(event) {
    const input = event.currentTarget;
    const file = input?.files?.[0] || null;
    if (input?.dataset.systemFlashFile === 'backup') state.flashBackupFile = file;
    if (input?.dataset.systemFlashFile === 'firmware') state.flashFirmwareFile = file;
    state.flashConfirm = '';
    state.flashMessage = '';
    state.flashError = '';
    render();
  }

  function onFlashPreserveInput(event) {
    state.flashPreserveText = String(event.currentTarget?.value || '');
    state.flashMessage = '';
    state.flashError = '';
    updateCodeLineNumbers(event.currentTarget);
  }

  function onFlashKeepSettingsChange(event) {
    state.flashKeepSettings = Boolean(event.currentTarget?.checked);
    state.flashConfirm = '';
  }

  function onSignatureUpdateFileSelect(event) {
    const file = event.currentTarget?.files?.[0] || null;
    if (!file) return;
    if (!/\.bin$/i.test(String(file.name || ''))) {
      state.signatureUpdateFile = null;
      state.signatureUpdateStatus = { kind: 'invalid-file', message: '特征库更新包必须是 tools/package-signature-update.sh 生成的 .bin 文件。' };
      render();
      return;
    }
    state.signatureUpdateFile = file;
    state.signatureUpdateStatus = {
      kind: 'selected',
      message: flashCapability('signature_update_browser_upload')
        ? '更新包已选择，可以提交后端校验。'
        : '更新包已选择；当前 Web API 尚未提供浏览器上传暂存入口。'
    };
    render();
  }

  function onFieldInput(event) {
    const el = event.currentTarget;
    if (el && (el.tagName === 'INPUT' || el.tagName === 'TEXTAREA') && el.type !== 'checkbox') {
      if (el.dataset.systemField) state.touchedFields.add(el.dataset.systemField);
      patchSystemSetting(el.dataset.systemField, typedFieldValue(el));
      refreshSavebarOnly();
      if (el.classList.contains('system-code-editor')) updateCodeLineNumbers(el);
    }
  }

  function onFieldChange(event) {
    const el = event.currentTarget;
    if (!el) return;
    if (el.dataset.systemField) state.touchedFields.add(el.dataset.systemField);
    patchSystemSetting(el.dataset.systemField, typedFieldValue(el));
    if (el.tagName === 'SELECT' || el.type === 'checkbox') {
      if (page === 'general' && state.tab === 'general' && (el.dataset.systemField === 'general.timezone' || el.dataset.systemField === 'general.time_format' || el.dataset.systemField === 'general.show_timezone_name')) {
        updateClockText();
      }
      refreshSavebarOnly();
      if (el.dataset.systemField === 'general.log_level') render();
    }
  }

  function typedFieldValue(el) {
    if (el.type === 'checkbox') return Boolean(el.checked);
    if (el.type === 'number' || el.type === 'range') {
      const value = Number(el.value);
      return Number.isFinite(value) ? value : 0;
    }
    return el.value;
  }

  function onNtpInput(event) {
    const index = Number(event.currentTarget.dataset.systemNtpIndex);
    const g = state.data.general || {};
    const servers = systemNtpServers(g);
    servers[index] = event.currentTarget.value;
    state.touchedFields.add('general.ntp_servers');
    patchSystemSetting('general.ntp_servers', servers);
    refreshSavebarOnly();
  }

  function onAvatarImageError(event) {
    if (!state.mounted) return;
    const badUrl = event.currentTarget?.getAttribute('src') || '';
    if (state.data.admin) {
      state.data.admin.avatar_broken_url = badUrl;
      state.data.admin.avatar_preview_url = '';
    }
    window.requestAnimationFrame(() => {
      if (state.mounted) render();
    });
  }

  function avatarExtension(file = {}) {
    const type = String(file.type || '').toLowerCase();
    if (type === 'image/jpeg') return 'jpg';
    if (type === 'image/webp') return 'webp';
    return 'png';
  }

  function avatarDataUrl(file) {
    return new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onload = () => resolve(String(reader.result || ''));
      reader.onerror = () => reject(new Error('读取图片失败'));
      reader.readAsDataURL(file);
    });
  }

  function avatarUrlFromResponse(result = {}) {
    return stringOr(
      result.avatar_url ||
      result.data?.avatar_url ||
      result.data?.data?.avatar_url ||
      result.body?.avatar_url
    );
  }

  async function onAvatarUpload(event) {
    const file = event.currentTarget?.files?.[0];
    if (!file) return;
    if (!/^image\/(png|jpeg|webp)$/.test(file.type || '')) {
      patchSystemSetting('admin.avatar_upload_error', '不支持的图片格式');
      render();
      return;
    }
    state.avatarWorking = true;
    patchSystemSetting('admin.avatar_upload_error', '');
    patchSystemSetting('admin.avatar_filename', file.name || '自定义头像');
    render();
    try {
      const dataUrl = await avatarDataUrl(file);
      const base64Content = dataUrl.slice(dataUrl.indexOf(',') + 1);
      const result = await postJson('/api/v1/system/admin/avatar', {
        username: state.data.admin?.username || 'root',
        base64_content: base64Content,
        ext: avatarExtension(file)
      });
      const avatarUrl = avatarUrlFromResponse(result);
      if (!avatarUrl) throw new Error('后端未返回头像地址');
      patchSystemSetting('admin.avatar_url', avatarUrl);
      patchSystemSetting('admin.avatar_preview_url', `${avatarUrl}${avatarUrl.includes('?') ? '&' : '?'}v=${Date.now()}`);
      patchSystemSetting('admin.avatar_broken_url', '');
      patchSystemSetting('admin.avatar_upload_error', '');
      state.touchedFields.delete('admin.avatar_url');
      if (state.baseline?.admin) state.baseline.admin.avatar_url = avatarUrl;
      window.dispatchEvent(new CustomEvent('dwrt:admin-avatar-changed', { detail: { avatar_url: avatarUrl } }));
      window.DreamingWrtNotify?.success?.('头像已更新');
    } catch (error) {
      patchSystemSetting('admin.avatar_upload_error', error?.message || '头像上传失败');
    } finally {
      state.avatarWorking = false;
      render();
    }
  }

  function patchSystemSetting(path, value) {
    if (!path) return;
    const parts = String(path).split('.').filter(Boolean);
    if (!parts.length) return;
    let node = state.data;
    while (parts.length > 1) {
      const key = parts.shift();
      const nextKey = parts[0];
      if (!node[key] || typeof node[key] !== 'object') node[key] = /^\d+$/.test(nextKey || '') ? [] : {};
      node = node[key];
    }
    node[parts[0]] = value;
    if (path === 'crontab.text') {
      state.data.crontab = { ...(state.data.crontab || {}), apply_requested_at: Math.floor(Date.now() / 1000) };
    } else if (path === 'startup.local_script') {
      state.data.startup = { ...(state.data.startup || {}), local_script_apply_requested_at: Math.floor(Date.now() / 1000) };
    }
    state.saveError = '';
    state.savedAt = 0;
  }

  function refreshSavebarOnly() {
    const current = root.querySelector('.dwrt-floating-savebar');
    if (!current) return;
    const wrapper = document.createElement('div');
    wrapper.innerHTML = systemSettingsSavebar().trim();
    const next = wrapper.firstElementChild;
    if (next) current.replaceWith(next);
  }

  function bindRootEvents() {
    root.addEventListener('click', onRootClick);
  }

  function onRootClick(event) {
    const savebarDiscard = event.target.closest('[data-dwrt-savebar-discard]');
    if (savebarDiscard && root.contains(savebarDiscard)) {
      event.preventDefault();
      discardChanges();
      return;
    }
    const savebarSave = event.target.closest('[data-dwrt-savebar-save]');
    if (savebarSave && root.contains(savebarSave)) {
      event.preventDefault();
      saveSystemSettings();
      return;
    }
    const tabBtn = event.target.closest('[data-system-general-tab]');
    if (tabBtn && root.contains(tabBtn)) {
      setTab(tabBtn.dataset.systemGeneralTab || 'general');
      render();
      event.preventDefault();
      return;
    }
    const startupTabBtn = event.target.closest('[data-system-startup-tab]');
    if (startupTabBtn && root.contains(startupTabBtn)) {
      setStartupTab(startupTabBtn.dataset.systemStartupTab || 'scripts');
      render();
      event.preventDefault();
      return;
    }
    const flashTabBtn = event.target.closest('[data-system-flash-tab]');
    if (flashTabBtn && root.contains(flashTabBtn)) {
      setFlashTab(flashTabBtn.dataset.systemFlashTab || 'operations');
      state.flashConfirm = '';
      state.flashMessage = '';
      state.flashError = '';
      render();
      if (state.flashTab === 'config' && !state.flashPreserveAvailable && !state.flashPreserveLoading) loadFlashPreserveConfig();
      event.preventDefault();
      return;
    }
    const advancedTabBtn = event.target.closest('[data-system-advanced-tab]');
    if (advancedTabBtn && root.contains(advancedTabBtn)) {
      setAdvancedTab(advancedTabBtn.dataset.systemAdvancedTab || 'performance');
      render();
      event.preventDefault();
      return;
    }
    const segment = event.target.closest('[data-system-segment]');
    if (segment && root.contains(segment)) {
      if (segment.dataset.systemSegment) state.touchedFields.add(segment.dataset.systemSegment);
      patchSystemSetting(segment.dataset.systemSegment, segment.dataset.systemValue || '');
      render();
      event.preventDefault();
      return;
    }
    const action = event.target.closest('[data-system-action]');
    if (!action || !root.contains(action)) return;
    const name = action.dataset.systemAction;
    event.preventDefault();
    if (name === 'ntp-add') addNtpServer();
    else if (name === 'ntp-remove') removeNtpServer(Number(action.dataset.ntpIndex));
    else if (name === 'discard') discardChanges();
    else if (name === 'save') saveSystemSettings();
    else if (name === 'sync-browser-time') syncTime('/api/v1/system/time-sync/browser');
    else if (name === 'sync-ntp-time') syncTime('/api/v1/system/time-sync/ntp');
    else if (name === 'binding-close') closeBindingDialog();
    else if (name === 'twofa-open-binding') openBindingDialog('otp');
    else if (name === 'api-open-pairing') openBindingDialog('app');
    else if (name === 'twofa-refresh-status') loadTwofaStatus(true);
    else if (name === 'twofa-prepare') prepareTwofa();
    else if (name === 'twofa-enable') enableTwofa();
    else if (name === 'twofa-disable') disableTwofa();
    else if (name === 'api-approve-pairing') approveAppPairing();
    else if (name === 'api-cancel-pairing') cancelAppPairing();
    else if (name === 'api-revoke-device') revokeAppDevice(action.dataset.apiId || '');
    else if (startupServiceActionFromDataset(name)) handleStartupServiceAction(action.dataset.serviceName || '', startupServiceActionFromDataset(name));
    else if (name === 'mount-generate-config') handleMountOperation('generate');
    else if (name === 'mount-connected-devices') handleMountOperation('connected');
    else if (name === 'mount-unmount') handleMountOperation('unmount', action.dataset.mountId || '');
    else if (name === 'mount-add' || name === 'mount-edit' || name === 'mount-delete') handleMountDraftAction(name, action.dataset.mountId || '');
    else if (name === 'flash-create-backup') createFlashBackup();
    else if (name === 'flash-restore-backup') unavailableBrowserFlashUpload('恢复配置');
    else if (name === 'flash-sysupgrade') unavailableBrowserFlashUpload('固件升级');
    else if (name === 'flash-factory-reset') factoryResetFlash();
    else if (name === 'flash-save-preserve') saveFlashPreserveConfig();
    else if (name === 'signature-apply-package') applySignatureUpdate();
    else if (name === 'advanced-kernel-restore-defaults') restoreAdvancedKernelDefaults();
  }

  function addNtpServer() {
    const servers = systemNtpServers(state.data.general || {});
    servers.push('');
    state.touchedFields.add('general.ntp_servers');
    patchSystemSetting('general.ntp_servers', servers);
    render();
  }

  function removeNtpServer(index) {
    const servers = systemNtpServers(state.data.general || {});
    if (servers.length <= 1) servers[0] = '';
    else servers.splice(index, 1);
    state.touchedFields.add('general.ntp_servers');
    patchSystemSetting('general.ntp_servers', servers);
    render();
  }


  function onCodeScroll(event) {
    const box = event.currentTarget?.closest('.system-code-editor-container');
    const nums = box?.querySelector('.system-code-line-numbers');
    if (nums) nums.scrollTop = event.currentTarget.scrollTop;
  }

  function updateCodeLineNumbers(textarea) {
    const box = textarea?.closest('.system-code-editor-container');
    const nums = box?.querySelector('.system-code-line-numbers');
    if (!nums) return;
    const count = Math.max(8, String(textarea.value || '').split(/\r?\n/).length);
    const current = nums.childElementCount;
    if (current === count) return;
    nums.innerHTML = Array.from({ length: count }, (_, index) => `<div>${index + 1}</div>`).join('');
    nums.scrollTop = textarea.scrollTop;
  }

  function captureScrollState() {
    if (!root) return null;
    const entries = [];
    root.querySelectorAll('[data-system-scroll]').forEach((el) => {
      entries.push({ key: el.dataset.systemScroll || '', top: el.scrollTop || 0, left: el.scrollLeft || 0 });
    });
    const stage = root.closest('.console-stage');
    return { pageTop: root.scrollTop || 0, stageTop: stage?.scrollTop || 0, entries };
  }

  function restoreScrollState(snapshot) {
    if (!snapshot || !root) return;
    window.requestAnimationFrame(() => {
      if (!state.mounted || !root) return;
      root.scrollTop = snapshot.pageTop || 0;
      const stage = root.closest('.console-stage');
      if (stage) stage.scrollTop = snapshot.stageTop || 0;
      (snapshot.entries || []).forEach((item) => {
        const el = root.querySelector(`[data-system-scroll="${cssEscape(item.key)}"]`);
        if (el) {
          el.scrollTop = item.top || 0;
          el.scrollLeft = item.left || 0;
          if (el.classList.contains('system-code-editor')) onCodeScroll({ currentTarget: el });
        }
      });
    });
  }

  function cssEscape(value) {
    if (window.CSS && typeof window.CSS.escape === 'function') return window.CSS.escape(String(value || ''));
    return String(value || '').replace(/["\\]/g, '\\$&');
  }

  function startupServiceActionFromDataset(actionName = '') {
    if (actionName === 'startup-service-toggle') return 'toggle';
    if (actionName === 'startup-service-start') return 'start';
    if (actionName === 'startup-service-restart') return 'restart';
    if (actionName === 'startup-service-reload') return 'reload';
    if (actionName === 'startup-service-stop') return 'stop';
    return '';
  }

  function updateStartupService(name, action) {
    const startup = state.data.startup || {};
    const services = Array.isArray(startup.services) ? startup.services : [];
    state.data.startup = {
      ...startup,
      services: services.map((svc) => {
        if (String(svc.name || svc.service || svc.id || '') !== String(name || '')) return svc;
        if (action === 'toggle') return { ...svc, enabled: !(svc.enabled !== false && svc.enable !== false && svc.autostart !== false), autostart: !(svc.enabled !== false && svc.enable !== false && svc.autostart !== false) };
        if (action === 'start' || action === 'restart' || action === 'reload') return { ...svc, running: true, status: 'running' };
        if (action === 'stop') return { ...svc, running: false, status: 'stopped' };
        return svc;
      }),
      last_action: { service: name, action, requested_at: Math.floor(Date.now() / 1000) }
    };
    state.saveError = '';
    state.savedAt = 0;
  }

  async function handleStartupServiceAction(serviceName, action) {
    if (!serviceName || !action || state.operationWorking) return;
    const startup = state.data.startup || {};
    const svc = (Array.isArray(startup.services) ? startup.services : []).find((item) => String(item.name || item.service || item.id || '') === String(serviceName));
    const enabled = svc ? (svc.enabled !== false && svc.enable !== false && svc.autostart !== false) : true;
    const mapped = action === 'toggle' ? (enabled ? 'disable' : 'enable') : action;
    state.operationWorking = `startup:${serviceName}:${action}`;
    render();
    try {
      const result = await postJson('/api/v1/system/startup/service-action', { service: serviceName, name: serviceName, action: mapped, confirm_critical: true });
      if (result && result.ok === false) throw new Error(result.error?.message || result.error || 'service action failed');
      updateStartupService(serviceName, action);
    } catch (error) {
      state.saveError = error?.message || 'service action failed';
    } finally {
      state.operationWorking = '';
      render();
    }
  }

  async function handleMountOperation(action, mountId = '') {
    const caps = state.data.capabilities || {};
    const key = action === 'generate' ? 'mounts_generate_config' : action === 'connected' ? 'mounts_mount_connected' : 'mounts_unmount';
    state.data.mounts = { ...(state.data.mounts || {}), last_action: { action, mount_id: mountId, requested_at: Math.floor(Date.now() / 1000) } };
    state.savedAt = 0;
    state.saveError = caps[key] === false ? '后端暂未提供这个挂载操作接口，已记录为待保存意图。' : '';
    if (action === 'generate') state.operationWorking = 'mount:generate';
    if (action === 'connected') state.operationWorking = 'mount:connected';
    render();
    window.setTimeout(() => {
      if (!state.mounted) return;
      state.operationWorking = '';
      refreshSavebarOnly();
      render();
    }, 450);
  }

  function handleMountDraftAction(actionName, mountId = '') {
    const action = actionName.replace(/^mount-/, '');
    state.data.mounts = { ...(state.data.mounts || {}), last_action: { action, mount_id: mountId, requested_at: Math.floor(Date.now() / 1000) } };
    if (action === 'delete' && mountId) {
      const points = Array.isArray(state.data.mounts.points) ? state.data.mounts.points : [];
      state.data.mounts.points = points.map((point) => mountActionId(point) === mountId ? { ...point, deleted: true, enabled: false, status: 'missing' } : point);
    }
    state.saveError = action === 'add' || action === 'edit' ? '挂载点编辑需要右侧编辑器/保存接口，已写入后端缺口。' : '';
    state.savedAt = 0;
    render();
  }

  function flashPayload(result) {
    return result?.data && typeof result.data === 'object' ? result.data : (result || {});
  }

  async function createFlashBackup() {
    if (state.flashWorking || !flashCapability('flash_backup_create')) return;
    state.flashWorking = 'create-backup';
    state.flashMessage = '';
    state.flashError = '';
    render();
    try {
      const payload = flashPayload(await postJson('/api/v1/system/flash/create_backup', {}));
      const path = stringOr(payload.path);
      const size = formatBytes(payload.size_bytes);
      state.data.flash = {
        ...(state.data.flash || {}),
        last_backup_at: Number(payload.ts || Math.floor(Date.now() / 1000)),
        backup_size: size,
        backup_path: path
      };
      state.flashMessage = path
        ? `备份已在设备上生成${size ? `（${size}）` : ''}。后端尚未提供浏览器下载地址：${path}`
        : '备份已生成，但后端没有返回文件路径或下载地址。';
    } catch (error) {
      state.flashError = error?.message || '生成备份失败';
    } finally {
      state.flashWorking = '';
      render();
    }
  }

  function unavailableBrowserFlashUpload(action) {
    state.flashConfirm = '';
    state.flashMessage = '';
    state.flashError = `${action}需要浏览器文件上传暂存接口；当前后端仅接受路由器本地文件路径。`;
    render();
  }

  async function factoryResetFlash() {
    if (state.flashWorking || !flashCapability('flash_factory_reset')) return;
    if (state.flashConfirm !== 'factory-reset') {
      state.flashConfirm = 'factory-reset';
      state.flashMessage = '请再次点击“恢复出厂设置”确认。';
      state.flashError = '';
      render();
      return;
    }
    state.flashWorking = 'factory-reset';
    state.flashConfirm = '';
    state.flashMessage = '';
    state.flashError = '';
    render();
    try {
      await postJson('/api/v1/system/flash/factory_reset', { confirm: true });
      state.flashMessage = '恢复出厂设置已启动，设备将重新启动。';
    } catch (error) {
      state.flashError = error?.message || '恢复出厂设置失败';
    } finally {
      state.flashWorking = '';
      render();
    }
  }

  async function loadFlashPreserveConfig() {
    if (state.flashPreserveLoading) return;
    state.flashPreserveLoading = true;
    state.flashError = '';
    render();
    try {
      const payload = flashPayload(await fetchJson('/api/v1/system/flash/preserve_config'));
      state.flashPreserveText = Array.isArray(payload.items) ? payload.items.map(stringOr).join('\n') : '';
      state.flashPreservePath = stringOr(payload.path || '/etc/sysupgrade.conf');
      state.flashPreserveAvailable = true;
    } catch (error) {
      state.flashPreserveAvailable = false;
      state.flashError = `无法读取保留配置清单：${error?.message || '接口不可用'}`;
    } finally {
      state.flashPreserveLoading = false;
      render();
    }
  }

  async function saveFlashPreserveConfig() {
    if (state.flashWorking || !state.flashPreserveAvailable) return;
    const items = String(state.flashPreserveText || '')
      .split(/\r?\n/)
      .map((item) => item.trim())
      .filter((item) => item && !item.startsWith('#'));
    const invalid = items.find((item) => !item.startsWith('/'));
    if (invalid) {
      state.flashError = `路径必须以 / 开头：${invalid}`;
      state.flashMessage = '';
      render();
      return;
    }
    state.flashWorking = 'save-preserve';
    state.flashMessage = '';
    state.flashError = '';
    render();
    try {
      await postJson('/api/v1/system/flash/preserve_config', { items });
      state.flashPreserveText = items.join('\n');
      state.flashMessage = `已保存 ${items.length} 条升级保留路径。`;
    } catch (error) {
      state.flashError = error?.message || '保存保留配置清单失败';
    } finally {
      state.flashWorking = '';
      render();
    }
  }

  async function applySignatureUpdate() {
    if (!state.signatureUpdateFile || state.flashWorking) return;
    const runtime = state.data.dreamingwrt?.signature_update || {};
    if (!(runtime.backend_ready && runtime.browser_upload_endpoint && runtime.apply_endpoint)) {
      state.signatureUpdateStatus = { kind: 'pending', message: 'jmxd 已有校验与应用方法，但 Web API 缺少浏览器上传暂存路由，当前不能安全提交本地文件。' };
      render();
      return;
    }
    state.signatureUpdateStatus = { kind: 'pending', message: '等待后端定义 opaque upload_id 合同后接入。' };
    render();
  }

  function advancedKernelDefaults() {
    return {
      nf_tcp_syn_sent: 5,
      nf_tcp_syn_recv: 5,
      nf_tcp_established: 1800,
      nf_tcp_fin_wait: 10,
      nf_tcp_close_wait: 10,
      nf_tcp_last_ack: 10,
      nf_tcp_time_wait: 10,
      nf_tcp_close: 5,
      nf_udp_timeout: 10,
      nf_udp_stream: 60,
      nf_icmp_timeout: 5
    };
  }

  async function restoreAdvancedKernelDefaults() {
    if (state.operationWorking) return;
    state.operationWorking = 'advanced:kernel-defaults';
    state.saveError = '';
    render();
    try {
      const result = await postJson('/api/v1/system/kernel/restore-defaults', { confirm: true });
      const payload = result?.data && typeof result.data === 'object' ? result.data : {};
      state.data.advanced = { ...(state.data.advanced || {}), ...advancedKernelDefaults(), ...payload };
      markBaseline(state.data);
      state.savedAt = Math.floor(Date.now() / 1000);
    } catch (error) {
      state.saveError = error?.message || '恢复内核默认配置失败';
    } finally {
      state.operationWorking = '';
      render();
    }
  }


  function discardChanges() {
    if (!state.baseline) return;
    state.data = normalizeSystemSettings(clone(state.baseline));
    state.saveError = '';
    state.savedAt = 0;
    render();
  }

  async function syncTime(url) {
    const button = root.querySelector(`[data-system-action="${url.includes('browser') ? 'sync-browser-time' : 'sync-ntp-time'}"]`);
    const oldText = button ? button.textContent : '';
    if (button) {
      button.disabled = true;
      button.textContent = '同步中...';
    }
    try {
      const result = await postJson(url, url.includes('browser') ? { timestamp: Math.floor(Date.now() / 1000), timezone: Intl.DateTimeFormat().resolvedOptions().timeZone || '' } : {});
      if (result && result.ok === false) throw new Error(result.error?.message || result.error || result.message || 'time sync failed');
      state.data.general.last_time_sync_at = Math.floor(Date.now() / 1000);
    } catch (error) {
      state.saveError = error?.message || 'time sync failed';
    } finally {
      if (button) {
        button.disabled = false;
        button.textContent = oldText;
      }
      refreshSavebarOnly();
    }
  }

  async function loadTwofaStatus(shouldRender = false) {
    try {
      const result = await fetchJson('/api/v1/auth/2fa/status');
      const payload = result?.data && typeof result.data === 'object' ? result.data : result;
      state.data = mergeSystemSettingsValue(state.data, { twofa: payload || {} });
      state.saveError = '';
      if (shouldRender) render();
    } catch (error) {
      state.saveError = error?.message || '2FA status unavailable';
      if (shouldRender) refreshSavebarOnly();
    }
  }

  async function loadAppDevices(shouldRender = false) {
    try {
      const result = await fetchJson('/api/v1/auth/devices');
      const payload = result?.data && typeof result.data === 'object' ? result.data : result;
      const devices = Array.isArray(payload?.devices) ? payload.devices : [];
      state.data = mergeSystemSettingsValue(state.data, { api: { paired_devices: devices } });
      state.saveError = '';
      if (shouldRender) render();
    } catch (error) {
      state.saveError = error?.message || 'paired devices unavailable';
      if (shouldRender) refreshSavebarOnly();
    }
  }

  async function prepareTwofa() {
    if (state.twofaWorking) return;
    state.twofaWorking = true;
    render();
    try {
      const result = await postJson('/api/v1/auth/2fa/prepare', {});
      const payload = result?.data && typeof result.data === 'object' ? result.data : result;
      state.data = mergeSystemSettingsValue(state.data, { twofa: payload || {} });
      markBaseline(state.data);
      state.saveError = '';
    } catch (error) {
      state.saveError = error?.message || '2FA prepare failed';
    } finally {
      state.twofaWorking = false;
      render();
    }
  }

  async function enableTwofa() {
    if (state.twofaWorking) return;
    const twofa = state.data.twofa || {};
    const secret = twofa.secret || '';
    const code = twofa.code || '';
    if (!secret || !code) {
      state.saveError = '请先准备绑定并输入验证码';
      refreshSavebarOnly();
      return;
    }
    state.twofaWorking = true;
    render();
    try {
      const result = await postJson('/api/v1/auth/2fa/enable', { secret, code });
      const payload = result?.data && typeof result.data === 'object' ? result.data : result;
      state.data = mergeSystemSettingsValue(state.data, { twofa: { ...(payload || {}), secret: '', otpauth_url: '', qr_svg: '', qr_png: '', code: '' } });
      markBaseline(state.data);
      state.saveError = '';
      state.bindingDialog = '';
    } catch (error) {
      state.saveError = error?.message || '2FA enable failed';
    } finally {
      state.twofaWorking = false;
      render();
    }
  }

  async function disableTwofa() {
    if (state.twofaWorking) return;
    const code = (state.data.twofa || {}).disable_code || '';
    if (!code) {
      state.saveError = '请输入当前验证码后解绑';
      refreshSavebarOnly();
      return;
    }
    state.twofaWorking = true;
    render();
    try {
      const result = await postJson('/api/v1/auth/2fa/disable', { code });
      const payload = result?.data && typeof result.data === 'object' ? result.data : result;
      state.data = mergeSystemSettingsValue(state.data, { twofa: { ...(payload || {}), secret: '', otpauth_url: '', qr_svg: '', qr_png: '', code: '', disable_code: '' } });
      markBaseline(state.data);
      state.saveError = '';
      state.bindingDialog = '';
    } catch (error) {
      state.saveError = error?.message || '2FA disable failed';
    } finally {
      state.twofaWorking = false;
      render();
    }
  }

  async function approveAppPairing() {
    if (state.pairWorking) return;
    const pairId = appDeviceId(state.pairCandidate || {});
    if (!pairId) return;
    state.pairWorking = true;
    render();
    try {
      // Web owner session grants the local confirmation the App is
      // blocked on (pair/confirm returns 409 pair_approval_required until
      // this lands). See BACKEND_ISSUES_FOR_BACKEND.md #1.
      await postJson('/api/v1/auth/pair/approve', { pair_id: pairId, app_device_id: pairId, approve: true });
      state.saveError = '';
      // Let the next devices poll flip pairState to 'paired'.
      pollPairingProgress();
    } catch (error) {
      state.saveError = error?.message || '批准失败，请确认当前为 Web owner 会话';
    } finally {
      state.pairWorking = false;
      render();
    }
  }

  async function cancelAppPairing() {
    if (state.pairWorking) return;
    const pairId = appDeviceId(state.pairCandidate || {});
    if (!pairId) return;
    state.pairWorking = true;
    render();
    try {
      await postJson('/api/v1/auth/pair/cancel', { pair_id: pairId, app_device_id: pairId });
      state.pairBaselineIds.push(pairId);
      state.pairCandidate = null;
      state.pairState = 'waiting';
      state.saveError = '';
    } catch (error) {
      state.saveError = error?.message || 'pair cancel failed';
    } finally {
      state.pairWorking = false;
      render();
      startPairStatusTimer();
    }
  }

  async function revokeAppDevice(id) {
    if (!id || state.deviceWorking) return;
    state.deviceWorking = id;
    render();
    try {
      await fetchJson(`/api/v1/auth/devices/${encodeURIComponent(id)}`, { method: 'DELETE' });
      await loadAppDevices(false);
      state.saveError = '';
    } catch (error) {
      state.saveError = error?.message || 'device revoke failed';
    } finally {
      state.deviceWorking = '';
      render();
    }
  }

  async function loadSystemSettings() {
    const loadId = ++state.seq;
    state.loading = true;
    state.error = '';
    render();
    const result = await fetchApi('systemSettings', ENDPOINT);
    if (!state.mounted || loadId !== state.seq) return;
    if (result.ok) {
      applyHydratedSettings(result.data || {});
      state.loading = false;
      state.error = '';
      state.saveError = '';
      render();
      if (page === 'admin') {
        await Promise.allSettled([loadTwofaStatus(false), loadAppDevices(false)]);
        if (!state.mounted || loadId !== state.seq) return;
        render();
      }
    } else {
      const drafts = new Map();
      state.touchedFields.forEach((path) => drafts.set(path, clone(valueAtPath(state.data, path))));
      const defaults = normalizeSystemSettings({});
      markBaseline(defaults);
      drafts.forEach((value, path) => setValueAtPath(defaults, path, value));
      state.data = defaults;
      state.loading = false;
      state.error = result.error?.message || 'system basic source is not available';
      render();
    }
    if (page === 'flash' && state.flashTab === 'config') loadFlashPreserveConfig();
  }


  async function refreshRuntimeForPage(shouldRender = false) {
    try {
      if (page === 'startup') {
        const result = await fetchJson('/api/v1/system/services');
        const payload = result?.data && typeof result.data === 'object' ? result.data : result;
        const services = Array.isArray(payload?.services) ? payload.services : [];
        state.data = mergeSystemSettingsValue(state.data, { startup: { services } });
      } else if (page === 'crontab') {
        const result = await fetchJson('/api/v1/system/cron');
        const payload = result?.data && typeof result.data === 'object' ? result.data : result;
        state.data = mergeSystemSettingsValue(state.data, { crontab: payload || {} });
      } else if (page === 'mounts') {
        const result = await fetchJson('/api/v1/system/mounts');
        const payload = result?.data && typeof result.data === 'object' ? result.data : result;
        state.data = mergeSystemSettingsValue(state.data, { mounts: payload || {} });
      }
      if (shouldRender) render();
    } catch (error) {
      if (!state.error) state.error = error?.message || 'runtime source unavailable';
      if (shouldRender) render();
    }
  }

  async function applySpecialSystemPageDraft(draft) {
    const updates = {};
    if (page === 'crontab') {
      const text = (draft.crontab || {}).text;
      if (typeof text === 'string') {
        const result = await postJson('/api/v1/system/crontab/apply', { text });
        const payload = result?.data && typeof result.data === 'object' ? result.data : result;
        updates.crontab = { ...(draft.crontab || {}), ...(payload || {}), text: typeof payload?.text === 'string' ? payload.text : text };
      }
    } else if (page === 'startup' && state.startupTab === 'local') {
      const content = (draft.startup || {}).local_script;
      if (typeof content === 'string') {
        const result = await postJson('/api/v1/system/startup/rc-local', { content, confirm_no_exit0: !/\bexit\s+0\b/.test(content) });
        const payload = result?.data && typeof result.data === 'object' ? result.data : result;
        updates.startup = { ...(draft.startup || {}), ...(payload?.content !== undefined ? { local_script: payload.content } : {}), ...(payload || {}) };
      }
    }
    return updates;
  }

  async function saveSystemSettings() {
    if (!dirty() || state.saving) return;
    state.saving = true;
    state.saveError = '';
    render();
    const draft = systemSettingsSaveDraft();
    let specialUpdates = {};
    try {
      specialUpdates = await applySpecialSystemPageDraft(draft);
      if (specialUpdates && Object.keys(specialUpdates).length) state.data = mergeSystemSettingsValue(state.data, specialUpdates);
    } catch (error) {
      state.saving = false;
      state.saveError = error?.message || 'apply failed';
      render();
      return;
    }
    let lastError = null;
    for (const url of SAVE_ENDPOINTS) {
      try {
        const requestPayload = systemSettingsRequestPayload(draft, specialUpdates);
        const result = await postJson(url, requestPayload);
        if (result && result.ok === false) throw new Error(result.error?.message || result.error || result.message || 'save failed');
        const data = result?.data && typeof result.data === 'object' ? result.data : requestPayload;
        state.data = mergeSystemSettingsValue(state.data, data);
        if (state.touchedFields.has('admin.new_password') || state.touchedFields.has('admin.confirm_password')) {
          state.data.admin.new_password = '';
          state.data.admin.confirm_password = '';
        }
        state.savedAt = Math.floor(Date.now() / 1000);
        markBaseline(state.data);
        state.touchedFields.clear();
        state.saving = false;
        render();
        return;
      } catch (error) {
        lastError = error;
      }
    }
    state.saving = false;
    state.saveError = lastError?.message || 'save endpoint unavailable';
    render();
  }

  function systemSettingsSaveDraft() {
    const draft = clone(state.data);
    const admin = {};
    const touched = state.touchedFields;
    if (touched.has('admin.username')) admin.username = state.data.admin?.username || '';
    if (touched.has('admin.new_password') || touched.has('admin.confirm_password')) {
      admin.new_password = state.data.admin?.new_password || '';
      admin.confirm_password = state.data.admin?.confirm_password || '';
    }
    if (touched.has('admin.web_login_timeout_min') && state.data.capabilities?.web_login_timeout === true) {
      admin.web_login_timeout_min = Math.max(1, Math.min(1440, Number(state.data.admin?.web_login_timeout_min || 60)));
    }
    if (Object.keys(admin).length) draft.admin = admin;
    else delete draft.admin;
    delete draft.admins;
    return draft;
  }

  function systemSettingsRequestPayload(draft, specialUpdates = {}) {
    const payload = mergeSystemSettingsValue(draft, specialUpdates);
    const admin = {};
    if (state.touchedFields.has('admin.username')) admin.username = state.data.admin?.username || '';
    if (state.touchedFields.has('admin.new_password') || state.touchedFields.has('admin.confirm_password')) {
      admin.new_password = state.data.admin?.new_password || '';
      admin.confirm_password = state.data.admin?.confirm_password || '';
    }
    if (state.touchedFields.has('admin.web_login_timeout_min') && state.data.capabilities?.web_login_timeout === true) {
      admin.web_login_timeout_min = Math.max(1, Math.min(1440, Number(state.data.admin?.web_login_timeout_min || 60)));
    }
    if (Object.keys(admin).length) payload.admin = admin;
    else delete payload.admin;
    delete payload.admins;
    return payload;
  }

  async function fetchJson(url, options = {}) {
    const response = await fetch(`${url}${url.includes('?') ? '&' : '?'}v=${encodeURIComponent(VERSION)}`, {
      credentials: 'same-origin',
      cache: 'no-store',
      headers: { ...(api.authHeaders ? api.authHeaders() : {}), ...(options.headers || {}) },
      ...options
    });
    const text = await response.text();
    let json = {};
    if (text) {
      try { json = JSON.parse(text); } catch (_) { throw new Error('invalid json'); }
    }
    if (!response.ok || json?.ok === false) {
      const message = json?.error?.message || json?.error?.code || json?.error || json?.message || `${response.status}`;
      const err = new Error(message);
      err.status = response.status;
      err.payload = json;
      throw err;
    }
    return json;
  }

  async function postJson(url, body) {
    const response = await fetch(`${url}${url.includes('?') ? '&' : '?'}v=${encodeURIComponent(VERSION)}`, {
      method: 'POST',
      credentials: 'same-origin',
      cache: 'no-store',
      headers: { 'Content-Type': 'application/json', ...(api.authHeaders ? api.authHeaders() : {}) },
      body: JSON.stringify(body || {})
    });
    const text = await response.text();
    let json = {};
    if (text) {
      try { json = JSON.parse(text); } catch (_) { throw new Error('invalid json'); }
    }
    if (!response.ok || json?.ok === false) {
      const message = json?.error?.message || json?.error?.code || json?.message || `${response.status}`;
      const err = new Error(message);
      err.status = response.status;
      err.payload = json;
      throw err;
    }
    return json;
  }

  function systemSettingsIcon(type) {
    if (type === 'rocket') return `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round"><path d="M14.5 5.5c2.5-2.5 5-2.5 5-2.5s0 2.5-2.5 5l-5 5-4-4 6.5-3.5Z"></path><path d="m9 12-4.5.5L3 14l4 1 1 4 1.5-1.5L10 13"></path><circle cx="15.5" cy="7" r="1.25"></circle></svg>`;
    if (type === 'antenna') return `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="1.5"></circle><path d="M8.5 8.5a5 5 0 0 0 0 7M15.5 8.5a5 5 0 0 1 0 7"></path><path d="M5.5 5.5a9.2 9.2 0 0 0 0 13M18.5 5.5a9.2 9.2 0 0 1 0 13"></path><path d="M12 13.5V21"></path></svg>`;
    if (type === 'balance') return `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3v18M6 6h12M5 6l-3 7h6L5 6ZM19 6l-3 7h6l-3-7Z"></path><path d="M2 13c.4 2 5.6 2 6 0M16 13c.4 2 5.6 2 6 0M8 21h8"></path></svg>`;
    if (type === 'tools') return `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round"><path d="M14.7 6.3a4 4 0 0 0-5-5L12 3.6 8.6 7 6.3 4.7a4 4 0 0 0 5 5L19 17.4a2.1 2.1 0 0 1-3 3l-7.7-7.7"></path><path d="m5 14-3 3 5 5 3-3"></path></svg>`;
    if (type === 'lab') return `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round"><path d="M9 3h6M10 3v5l-5.5 9.5A2.3 2.3 0 0 0 6.5 21h11a2.3 2.3 0 0 0 2-3.5L14 8V3"></path><path d="M7.5 15h9"></path><circle cx="10" cy="18" r=".7" fill="currentColor" stroke="none"></circle></svg>`;
    if (type === 'route') return `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round"><circle cx="6" cy="19" r="2"></circle><circle cx="18" cy="5" r="2"></circle><path d="M8 19h3a3 3 0 0 0 3-3V8a3 3 0 0 1 3-3h-1"></path><path d="m9 7 3-3 3 3"></path></svg>`;
    if (type === 'identity') return `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="4" width="18" height="16" rx="3"></rect><path d="M8 10h8M8 14h5"></path><path d="M7 4v16M17 4v16"></path></svg>`;
    if (type === 'clock') return `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="9"></circle><path d="M12 7v5l3 2"></path></svg>`;
    if (type === 'terminal') return `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="4" width="18" height="16" rx="2"></rect><path d="m7 9 3 3-3 3"></path><path d="M12 15h5"></path></svg>`;
    if (type === 'globe') return `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="9"></circle><path d="M3 12h18"></path><path d="M12 3a14 14 0 0 1 0 18M12 3a14 14 0 0 0 0 18"></path></svg>`;
    if (type === 'disk') return `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round"><path d="M4 5a2 2 0 0 1 2-2h10l4 4v12a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2z"></path><path d="M8 3v6h8"></path><path d="M8 17h8"></path></svg>`;
    if (type === 'gear') return `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round"><path d="M9.7 4.1a2.3 2.3 0 0 1 4.6 0 2.3 2.3 0 0 0 3.3 1.9 2.3 2.3 0 0 1 2.3 4 2.3 2.3 0 0 0 0 3.8 2.3 2.3 0 0 1-2.3 4 2.3 2.3 0 0 0-3.3 1.9 2.3 2.3 0 0 1-4.6 0 2.3 2.3 0 0 0-3.3-1.9 2.3 2.3 0 0 1-2.3-4 2.3 2.3 0 0 0 0-3.8 2.3 2.3 0 0 1 2.3-4 2.3 2.3 0 0 0 3.3-1.9"></path><circle cx="12" cy="12" r="3"></circle></svg>`;
    if (type === 'hourglass') return `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round"><path d="M6 3h12M6 21h12"></path><path d="M7 3c0 5 10 5 10 9s-10 4-10 9"></path><path d="M17 3c0 5-10 5-10 9s10 4 10 9"></path></svg>`;
    if (type === 'sync') return `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round"><path d="M20 11a8.1 8.1 0 0 0-15.5-2M4 5v4h4"></path><path d="M4 13a8.1 8.1 0 0 0 15.5 2M20 19v-4h-4"></path></svg>`;
    if (type === 'language') return `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round"><path d="M4 5h10M9 3v2"></path><path d="M5 9c2.5 4 6.5 6 10 7"></path><path d="M13 5c-1 5-4 8-8 10"></path><path d="M14 19l4-9 4 9"></path><path d="M15.5 16h5"></path></svg>`;
    if (type === 'palette') return `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3a9 9 0 0 0 0 18h1.5a1.8 1.8 0 0 0 1.2-3.1 1.8 1.8 0 0 1 1.2-3.1H17a4 4 0 0 0 4-4c0-4.3-4-7.8-9-7.8z"></path><circle cx="7.5" cy="10.5" r=".8"></circle><circle cx="10.5" cy="7.5" r=".8"></circle><circle cx="14.5" cy="7.5" r=".8"></circle></svg>`;
    if (type === 'search') return `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round"><circle cx="11" cy="11" r="7"></circle><path d="m20 20-3.5-3.5"></path></svg>`;
    if (type === 'close') return `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round"><path d="m6 6 12 12M18 6 6 18"></path></svg>`;
    if (type === 'phone') return `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round"><rect x="7" y="2.5" width="10" height="19" rx="2"></rect><path d="M10.5 18h3"></path></svg>`;
    if (type === 'android') return `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round"><rect x="5" y="7" width="14" height="12" rx="3"></rect><path d="M8 7 6 4M16 7l2-3M9 12h.01M15 12h.01"></path></svg>`;
    if (type === 'shield') return `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path><path d="m9 12 2 2 4-5"></path></svg>`;
    if (type === 'key') return `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round"><circle cx="7.5" cy="14.5" r="4.5"></circle><path d="M11 11l7-7"></path><path d="M15 5l4 4"></path><path d="M17 7l-2 2"></path></svg>`;
    if (type === 'upload') return `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path><path d="M17 8l-5-5-5 5"></path><path d="M12 3v12"></path></svg>`;
    if (type === 'download') return `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path><path d="m7 10 5 5 5-5"></path><path d="M12 15V3"></path></svg>`;
    if (type === 'restore') return `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round"><path d="M3 12a9 9 0 1 0 3-6.7L3 8"></path><path d="M3 3v5h5"></path><path d="M12 7v5l3 2"></path></svg>`;
    if (type === 'warning') return `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round"><path d="M10.3 3.4 2.7 17a2 2 0 0 0 1.8 3h15a2 2 0 0 0 1.8-3L13.7 3.4a2 2 0 0 0-3.4 0Z"></path><path d="M12 9v4"></path><path d="M12 17h.01"></path></svg>`;
    if (type === 'file') return `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8Z"></path><path d="M14 2v6h6"></path><path d="M8 13h8M8 17h6"></path></svg>`;
    if (type === 'database') return `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round"><ellipse cx="12" cy="5" rx="8" ry="3"></ellipse><path d="M4 5v6c0 1.7 3.6 3 8 3s8-1.3 8-3V5"></path><path d="M4 11v6c0 1.7 3.6 3 8 3s8-1.3 8-3v-6"></path></svg>`;
    if (type === 'edit') return `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round"><path d="M12 20h9"></path><path d="M16.5 3.5a2.1 2.1 0 0 1 3 3L7 19l-4 1 1-4 12.5-12.5Z"></path></svg>`;
    if (type === 'delete') return `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round"><path d="M4 7h16"></path><path d="M10 11v6M14 11v6"></path><path d="M6 7l1 14h10l1-14"></path><path d="M9 7V4h6v3"></path></svg>`;
    if (type === 'zram') return `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round"><rect x="5" y="5" width="14" height="14" rx="3"></rect><path d="M9 9h6v6H9z"></path><path d="M9 2v3M15 2v3M9 19v3M15 19v3M2 9h3M2 15h3M19 9h3M19 15h3"></path></svg>`;
    return `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round"><rect x="5" y="4" width="14" height="16" rx="2"></rect><path d="M9 8h6M9 12h6M9 16h3"></path></svg>`;
  }

  root.classList.add(MODULE_CLASS);
  bindRootEvents();
  document.addEventListener('keydown', onBindingDialogKeydown, true);
  loadSystemSettings();
  state.clockTimer = window.setInterval(updateClockText, 1000);

  return {
    unmount() {
      state.mounted = false;
      if (state.timer) window.clearTimeout(state.timer);
      if (state.clockTimer) window.clearInterval(state.clockTimer);
      stopPairStatusTimer();
      document.removeEventListener('keydown', onBindingDialogKeydown, true);
      if (root) {
        root.classList.remove(MODULE_CLASS);
        root.removeEventListener('click', onRootClick);
      }
    }
  };
}

export default { mount };
