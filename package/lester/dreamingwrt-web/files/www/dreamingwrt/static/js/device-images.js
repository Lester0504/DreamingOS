(() => {
  'use strict';

  const BRAND_LOGO_BASE = '/static/images/logo/';
  const runtimeOverrides = new Map();
  const BRAND_ALIASES = [
    [/\b(ikuai|ikuaios|i-kuai)\b|爱快/i, 'ikuai'],
    [/\b(apple|iphone|ipad|macbook|macintosh)\b/i, 'apple'],
    [/\b(synology|diskstation|dsm)\b/i, 'synology'],
    [/\bproxmox\b/i, 'proxmox'],
    [/\b(gldotinet|gl[-\s.]?inet)\b|golden\s*dot/i, 'gldotinet'],
    [/\b(ubiquiti|unifi)\b/i, 'ubiquiti'],
    [/\b(xiaomi|redmi)\b|小米/i, 'xiaomi'],
    [/\b(huawei|honor)\b|华为|荣耀/i, 'huawei'],
    [/\b(samsung|galaxy)\b|三星/i, 'samsung'],
    [/\b(google|pixel|chromecast)\b/i, 'google'],
    [/\b(microsoft|windows|xbox)\b/i, 'microsoft'],
    [/\btp[-\s]?link\b|\btplink\b/i, 'tp-link'],
    [/\bqnap\b/i, 'qnap'],
    [/\b(truenas|true\s*nas)\b/i, 'truenas'],
    [/\b(freenas|free\s*nas)\b/i, 'freenas'],
    [/\bunraid\b/i, 'unraid'],
    [/\bmikrotik\b/i, 'mikrotik'],
    [/\b(nintendo|gamecube|wii)\b/i, 'nintendo'],
    [/\boppo\b/i, 'oppo'],
    [/\bvivo\b/i, 'vivo'],
    [/\bzte\b|中兴/i, 'zte'],
    [/\b(dell|alienware)\b/i, 'dell'],
    [/\bacer\b/i, 'acer'],
    [/\bintel\b/i, 'intel'],
    [/\bubuntu\b/i, 'ubuntu'],
    [/\bdebian\b/i, 'debian'],
    [/\bfedora\b/i, 'fedora'],
    [/\bfreebsd\b/i, 'freebsd'],
    [/\bopenbsd\b/i, 'openbsd'],
    [/\bred\s*hat\b|\bredhat\b/i, 'red-hat'],
    [/\blinux\b/i, 'linux'],
    [/\bhome\s*assistant\b/i, 'home-assistant'],
    [/\bplex\b/i, 'plex'],
    [/\btesla\b/i, 'tesla'],
    [/\b(amazon|kindle|echo)\b|\bfire\s*tv\b/i, 'amazon'],
    [/\bnokia\b/i, 'nokia'],
    [/\bmeizu\b|魅族/i, 'meizu'],
    [/\blg\b|\blg electronics\b/i, 'lg'],
    [/\blinksys\b/i, 'linksys'],
    [/\bepson\b/i, 'epson'],
    [/\bbose\b/i, 'bose'],
    [/\bjbl\b/i, 'jbl'],
    [/\bhoneywell\b/i, 'honeywell'],
    [/\b(irobot|roomba)\b/i, 'irobot'],
    [/\bring\b/i, 'ring'],
    [/\bvalve\b|steam deck/i, 'valve'],
    [/\bmsi\b|micro-star/i, 'msi'],
    [/\bibm\b/i, 'ibm'],
    [/\b(avm|fritz)\b/i, 'avm'],
    [/\btecno\b/i, 'tecno'],
    [/\bsony\b(?:\s*(group|corp|corporation))?|\b(playstation|bravia)\b/i, 'sony-group']
  ];

  function text(value) {
    if (value === undefined || value === null) return '';
    if (typeof value === 'object') {
      return text(value.web_image || value.url || value.path || value.src || value.image || value.icon);
    }
    return String(value).trim();
  }

  function first(...values) {
    for (const value of values) {
      const normalized = text(value);
      if (normalized) return normalized;
    }
    return '';
  }

  function normalizeUrl(value) {
    const source = text(value);
    if (!source || /^(?:data|blob):/i.test(source)) return source;
    if (/^(?:https?:)?\/\//i.test(source)) return source;
    if (source.startsWith(BRAND_LOGO_BASE)) return source;
    const movedRootLogo = source.match(/^\/static\/images\/(china-(?:cernet|mobile|telecom|unicom)\.svg|dreamingwrt\.png|logo-64\.png)(?:[?#].*)?$/i);
    if (movedRootLogo) return `${BRAND_LOGO_BASE}${encodeURIComponent(movedRootLogo[1])}`;
    const legacyPrefixes = [
      '/luci-static/dreamingwrt/dashboard/assets/app_icons/',
      '/luci-static/resources/app_icons/',
      '/static/images/brand-logos/',
      '/www/dreamingwrt/static/images/logo/',
      'icons/'
    ];
    const prefix = legacyPrefixes.find((candidate) => source.startsWith(candidate));
    if (!prefix) return source;
    const file = source.slice(prefix.length).split(/[?#]/)[0].split('/').pop();
    return file ? `${BRAND_LOGO_BASE}${encodeURIComponent(file)}` : '';
  }

  function fingerprintOf(device = {}) {
    return device.fingerprintData && typeof device.fingerprintData === 'object'
      ? device.fingerprintData
      : device.fingerprint && typeof device.fingerprint === 'object'
        ? device.fingerprint
        : {};
  }

  function brandSlug(...values) {
    const source = values.map(text).filter(Boolean).join(' ');
    if (!source) return '';
    const match = BRAND_ALIASES.find(([pattern]) => pattern.test(source));
    return match ? match[1] : '';
  }

  function brandLogoUrl(device = {}) {
    const fingerprint = fingerprintOf(device);
    const slug = brandSlug(
      device.vendor_name, device.vendor, device.manufacturer, device.brand,
      device.model, device.device_model, device.device_name,
      device.display_name, device.name, device.hostname,
      fingerprint.vendor_name, fingerprint.vendor,
      fingerprint.fingerprint_device_vendor,
      fingerprint.device_name, fingerprint.fingerprint_device_name
    );
    return slug ? `${BRAND_LOGO_BASE}${slug}.svg` : '';
  }

  function resolve(device = {}) {
    const fingerprint = fingerprintOf(device);
    const mac = first(device.mac, device.client_mac, device.hwaddr, device.id).toLowerCase();
    const runtime = mac && runtimeOverrides.get(mac);
    if (runtime) return { src: normalizeUrl(runtime), kind: 'runtime-override', priority: 120 };
    const custom = first(
      device.custom_image_path,
      device.custom_icon,
      device.override_image,
      device.override_icon,
      fingerprint.custom_image_path,
      fingerprint.custom_icon,
      fingerprint.override_image,
      fingerprint.override_icon
    );
    if (custom) return { src: normalizeUrl(custom), kind: 'custom', priority: 100 };

    const identified = first(
      device.image_url,
      device.web_image,
      device.image,
      device.icon_url,
      device.icon,
      device.fingerprint_image,
      fingerprint.image_url,
      fingerprint.web_image,
      fingerprint.image,
      fingerprint.icon
    );
    if (identified) return { src: normalizeUrl(identified), kind: 'fingerprint', priority: 80 };

    const brand = brandLogoUrl(device);
    if (brand) return { src: brand, kind: 'brand', priority: 60 };
    return { src: '', kind: 'fallback', priority: 0 };
  }

  window.DWRT_DEVICE_IMAGES = Object.freeze({
    brandLogoUrl,
    brandSlug,
    normalizeUrl,
    resolve,
    setOverride(mac, src) {
      const key = text(mac).toLowerCase();
      const value = normalizeUrl(src);
      if (!key) return;
      if (value) runtimeOverrides.set(key, value);
      else runtimeOverrides.delete(key);
    },
    text
  });
})();
