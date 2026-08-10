export function mount(context = {}) {
  const root = context.root || document.getElementById('routePreview');
  const api = context.api || {};
  const utils = context.utils || {};
  const ui = context.ui || {};
  const escapeHtml = utils.escapeHtml || ((value) => String(value ?? '').replace(/[&<>"']/g, (ch) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[ch])));
  const fetchApi = api.fetch || (async (name, url) => {
    const response = await sessionFetch(url, { credentials: 'same-origin', cache: 'no-store' });
    const json = await response.json().catch(() => ({}));
    return { name, ok: response.ok && json?.ok !== false, data: json?.data ?? json, raw: json };
  });

  const VERSION = '20260809-policy-table-acl-pending-reasons-01';
  const ENDPOINT = '/api/v1/policy-engine/policy-table';
  const CATALOG_ENDPOINT = '/api/v1/policy-engine/catalog';
  /*
   * 应用候选每页取多少。后端 webd_policy_catalog_collect_applications() 的硬上限是
   * 500（超过就被夹到 500），默认 100。这里直接按上限取，配合 app_offset 翻页；
   * 只把 limit 顶到 500 是不够的 —— 库里 5873 个应用，500 仍然覆盖不到。
   */
  const APP_PAGE_SIZE = 500;
  /* 端口转发要显示的 WAN 出口地址只有这个接口给：policy-engine 的 zones/catalog
     里一个 IP 字段都没有（wan zone 只有 members/name/type 之类），以前从
     catalog.wans[].raw 里取 public_ip/ip 恒为空，于是永远落到兜底文案。 */
  const WANS_ENDPOINT = '/api/v1/network/wans';
  /* PBR 的 target 填的是 route_table.id（后端 nc_adv_table_id_by_name() 在
     route_table 表里查），不是接口名。catalog.wans 里有 wan3/wan4，但账本
     route_table 里可能没有对应行 —— 用 wans 当出口选项会让用户选出一条必然
     失效的规则，所以出口候选只能来自这个接口。列表挂在 items 上。 */
  const ROUTING_TABLES_ENDPOINT = '/api/v1/routing/tables';
  /* zone 源要列的是防火墙 zone。catalog.source_zones 已含 dw_lan2，够用；
     这个接口只在 catalog 缺 zone 时兜底，并提供 members 供提示文案使用。 */
  const ZONES_ENDPOINT = '/api/v1/policy-engine/zones';
  /* MAC ACL 与「终端联网控制」共用同一底座（config.db:network_control_rule
     + nftables）。本页同样承载 MAC ACL 的创建与编辑：既然类型选择器里放了
     ACL 这一项，它就必须能填完并保存，否则用户看到的是一个坏掉的入口。
     这个路由只用于"去那一页查看同一条规则"的旁路链接，不再是唯一写入面。 */
  const ACL_MAC_ROUTE = '/authentication/client-network-control';
  /*
   * 「地区」候选项来自 country 类型的 flowd 流量对象（webd catalog 按 type 分流，
   * jmx_app_api.c:35646），而这类对象的写入面在对象页。空态只说“暂无数据”会让
   * 用户以为后端缺失，实际是要先去建一个对象，所以空态直接给跳转。
   */
  const FLOW_OBJECT_ROUTE = '/policy-engine/objects';
  const MODULE_CLASS = 'policy-table-route-host';
  /* 绑定去重记录：selector -> 已绑过的节点集合（见 scopedAll）。
     用 WeakSet 而不是 dataset 标记，因为同一个节点可能匹配多个选择器，
     单个 dataset 键会互相覆盖，导致某一路绑定被重复叠加。 */
  const boundNodes = new Map();
  const DEFAULT_COLUMNS = [
    { key: 'expand', label: '', fixed: true, min: 46 },
    { key: 'name', label: '名称', min: 240 },
    { key: 'type', label: '策略类型', min: 132 },
    { key: 'action', label: '操作', min: 100 },
    { key: 'protocol', label: '协议', min: 112 },
    { key: 'source_zone', label: '源区域', min: 116 },
    { key: 'source', label: '源', min: 156 },
    { key: 'destination_zone', label: '目标区域', min: 116 },
    { key: 'destination', label: '目标', min: 156 },
    { key: 'destination_port', label: '目标端口', min: 112 },
    { key: 'interface', label: '接口', min: 120 }
  ];
  const FALLBACK_FILTERS = {
    policy_type: [
      { value: 'all', label: '所有策略', count: 0 },
      { value: 'acl', label: 'ACL 规则', count: 0, disabled: true },
      { value: 'dns', label: 'DNS 记录', count: 0, disabled: true },
      { value: 'firewall', label: '防火墙', count: 0 },
      { value: 'nat', label: 'NAT 规则', count: 0 },
      { value: 'pbr', label: '基于策略的路由', count: 0, disabled: true },
      { value: 'port_forwarding', label: '端口转发', count: 0, disabled: true },
      { value: 'qos', label: 'QoS 规则', count: 0, disabled: true },
      { value: 'static_route', label: '静态路由', count: 0, disabled: true }
    ],
    action: [
      { value: 'convert', label: '转换', count: 0 },
      { value: 'allow', label: '允许', count: 0 },
      { value: 'block', label: '阻止', count: 0 },
      { value: 'reject', label: '拒绝', count: 0 }
    ],
    protocol: [],
    source: [],
    destination: [],
    interface: []
  };
  const EMPTY_CATALOG = {
    policy_types: [], actions: [], protocols: [], ip_versions: [], connection_states: [],
    source_zones: [], destination_zones: [], networks: [], interfaces: [], wans: [],
    devices: [], objects: [], applications: [], regions: [], schedules: []
  };
  const state = {
    rows: [],
    filters: structuredCloneSafe(FALLBACK_FILTERS),
    source: '',
    capabilities: {},
    catalog: structuredCloneSafe(EMPTY_CATALOG),
    catalogError: '',
    /* name -> { ip, public_ip } ，来自 network/wans；空对象表示还没读到。 */
    wanAddresses: {},
    wanAddressState: 'idle',
    /* PBR 出口候选：routing/tables 的 items，形如 { id, table_id, role }。
       空数组既可能是没读到也可能是账本真的没有表，两者都要拦住保存。 */
    routeTables: [],
    routeTablesState: 'idle',
    /* zone id -> members[]，只用于源选择器的成员提示。 */
    zoneMembers: {},
    /*
     * 应用目录是唯一需要服务端分页的候选源：库里有 5873 个应用，catalog 单页
     * 上限 500，所以既不能全量缓存，也不能像其他候选源那样只过滤本地 DOM。
     * total 是当前查询条件下的全集大小（不是已取回的条数），has_more 由后端算，
     * 前端不用「returned < limit」去猜末页。
     */
    appCatalog: {
        query: '',
        loaded: 0,
        total: 0,
        hasMore: false,
        loading: false,
        error: '',
        seq: 0
    },
    error: '',
    loading: true,
    drawerOpen: false,
    columnsOpen: false,
    createOpen: false,
    detailsOpen: false,
    selectedRow: null,
    draft: {},
    saving: false,
    notice: '',
    pickerOpen: '',
    bulkInputs: new Set(),
    confirmDelete: false,
    query: '',
    showDefault: true,
    type: 'all',
    selectedFilters: { action: new Set(), protocol: new Set(), source: new Set(), destination: new Set(), interface: new Set() },
    collapsed: new Set(),
    expandedRows: new Set(),
    visibleColumns: new Set(DEFAULT_COLUMNS.map((column) => column.key)),
    seq: 0,
    abort: null
  };

  let mounted = true;
  let searchTimer = 0;
  /*
   * 应用搜索的防抖状态。appSearchQuery 保存用户正在打的原文（未 trim），
   * 因为 patchOverlays() 换掉抽屉正文后输入框是新节点，值必须从这里回填。
   */
  let appSearchTimer = 0;
  let appSearchQuery = '';

  function structuredCloneSafe(value) {
    try { return structuredClone(value); } catch (_) { return JSON.parse(JSON.stringify(value)); }
  }
  function asArray(value) {
    if (Array.isArray(value)) return value;
    if (Array.isArray(value?.items)) return value.items;
    if (Array.isArray(value?.rows)) return value.rows;
    if (Array.isArray(value?.policies)) return value.policies;
    if (Array.isArray(value?.data)) return value.data;
    return [];
  }
  function firstText(...values) {
    for (const value of values) {
      if (value === undefined || value === null) continue;
      if (Array.isArray(value)) {
        const nested = value.map((item) => firstText(item)).filter(Boolean);
        if (nested.length) return nested.join(' ');
        continue;
      }
      if (typeof value === 'object') {
        const nested = firstText(value.label, value.name, value.display_name, value.value, value.id, value.key);
        if (nested) return nested;
        continue;
      }
      const text = String(value).trim();
      if (text) return text;
    }
    return '';
  }
  function normalizeKey(value) {
    return String(value || '').trim().toLowerCase().replace(/[\s_-]+/g, '_');
  }
  function actionLabel(value) {
    const key = normalizeKey(value);
    if (['allow', 'accept', 'permit'].includes(key)) return '允许';
    if (['block', 'drop', 'deny'].includes(key)) return '阻止';
    if (['reject'].includes(key)) return '拒绝';
    if (['convert', 'translate', 'nat', 'masquerade'].includes(key)) return '转换';
    return firstText(value) || '--';
  }
  function actionKey(value) {
    const key = normalizeKey(value);
    if (['allow', 'accept', 'permit'].includes(key)) return 'allow';
    if (['block', 'drop', 'deny'].includes(key)) return 'block';
    if (['reject'].includes(key)) return 'reject';
    if (['convert', 'translate', 'nat', 'masquerade'].includes(key)) return 'convert';
    return key || 'unknown';
  }
  function routeFamilyKey(value) {
    const key = normalizeKey(value);
    if (!key) return '';
    if (key === 'static_route' || key === 'static_routes' || key === 'route' || key === 'route6' || key === 'staticroute' || key.includes('static_route') || key.includes('static-route')) return 'static_route';
    if (key === 'pbr' || key.includes('policy_based_route') || key.includes('policy_route') || key.includes('mwan')) return 'pbr';
    return '';
  }
  function typeLabel(value, row = {}) {
    const key = normalizeKey(value || row.policy_type || row.type_key || row.kind);
    const routeKey = routeFamilyKey(key);
    if (routeKey === 'static_route') return '静态路由';
    if (routeKey === 'pbr') return '基于策略的路由';
    if (key.includes('firewall')) return '防火墙';
    if (key.includes('nat')) return firstText(row.nat_type_label, row.nat_type) || '伪装 NAT';
    if (key.includes('acl')) return 'ACL 规则';
    if (key.includes('dns')) return 'DNS 记录';
    if (key.includes('qos')) return 'QoS 规则';
    if (key.includes('port')) return '端口转发';
    if (key.includes('route')) return '基于策略的路由';
    return firstText(value, row.type, row.policy_type) || '--';
  }
  function policyTypeKey(row = {}) {
    const key = normalizeKey(row.policy_type || row.type_key || row.kind || row.type);
    const routeKey = routeFamilyKey(key);
    if (routeKey) return routeKey;
    if (key.includes('firewall') || row.type === '防火墙') return 'firewall';
    if (key.includes('nat') || String(row.type || '').includes('NAT')) return 'nat';
    if (key.includes('acl')) return 'acl';
    if (key.includes('dns')) return 'dns';
    if (key.includes('qos')) return 'qos';
    if (key.includes('port')) return 'port_forwarding';
    if (key.includes('route')) return 'pbr';
    return key || 'unknown';
  }
  function valueList(value) {
    if (Array.isArray(value)) return value.map((item) => firstText(item)).filter(Boolean);
    const text = firstText(value);
    return text ? [text] : [];
  }
  function cellText(value, fallback = '--') {
    const list = valueList(value);
    if (!list.length) return fallback;
    return list.join(' ');
  }
  function compactValue(value) {
    const list = valueList(value);
    if (!list.length) return '<span class="policy-muted">--</span>';
    if (list.length > 1) return `<span class="policy-pill">多个</span>`;
    const text = list[0];
    if (text.length > 22) return `<span class="policy-pill" title="${escapeHtml(text)}">${escapeHtml(text.slice(0, 18))}…</span>`;
    if (/^(Default|Gateway|Internet|fe80|224\.|ff02|多个)$/i.test(text) || text.includes('::')) return `<span class="policy-pill">${escapeHtml(text)}</span>`;
    return escapeHtml(text);
  }
  /*
   * 源列文案。后端给的 source_display 形如 `zone:dw_lan2`，这里译成中文；
   * 没有 source_display 时返回空串，让调用方沿用原来的兜底链。
   */
  function pbrSourceCellText(row = {}) {
    const raw = row.raw && typeof row.raw === 'object' ? row.raw : row;
    const display = firstText(raw.source_display, row.source_display);
    const kind = normalizeKey(firstText(raw.source_kind, row.source_kind));
    const ref = firstText(raw.source_ref, row.source_ref);
    if (!display && (!kind || kind === 'object' || !ref)) return '';
    const labels = { interface: '接口', zone: '区域', network: '网络' };
    const parts = String(display || `${kind}:${ref}`).split(':');
    const kindKey = normalizeKey(parts[0]) || kind;
    const refText = parts.slice(1).join(':') || ref;
    if (!refText) return '';
    const pinned = raw.pin_wan === true || row.pin_wan === true;
    return `${labels[kindKey] || kindKey}：${refText}${pinned ? '（固定出口）' : ''}`;
  }
  function normalizeRow(row = {}, index = 0, fallbackType = '') {
    const source = row.source || {};
    const destination = row.destination || row.target || {};
    const normalized = {
      id: firstText(row.id, row._id, row.uuid, row.origin_id, row.name) || `policy-${index}`,
      name: firstText(row.name, row.label, row.description, row.rule_name) || `策略 ${index + 1}`,
      type: typeLabel(row.policy_type || row.type || fallbackType, row),
      policy_type: policyTypeKey({ ...row, policy_type: row.policy_type || fallbackType }),
      action: actionLabel(row.action || row.operation || row.rule_action),
      action_key: actionKey(row.action || row.operation || row.rule_action),
      protocol: firstText(row.protocol_label, row.protocol, row.ip_protocol, row.proto) || '全部',
      source_zone: firstText(row.source_zone, row.source_zone_name, source.zone, source.zone_name, row.source?.zone_id) || '-',
      /* source_display 优先：接口/zone 规则的 source_object 是空的，
         直接渲染它会落到「任何」，把一条只匹配 lan2 的规则读成匹配全部。 */
      source: pbrSourceCellText(row) || firstText(row.source_label, row.source_name, row.source, source.matching_target, source.address, source.network, source.name) || '任何',
      destination_zone: firstText(row.destination_zone, row.destination_zone_name, destination.zone, destination.zone_name, destination.zone_id) || '-',
      destination: firstText(row.destination_label, row.destination_name, row.destination, destination.matching_target, destination.address, destination.network, destination.name) || '任何',
      destination_port: firstText(row.destination_port, row.dst_port, row.port, row.ports, destination.port, destination.ports) || '任何',
      interface: firstText(row.interface, row.interface_name, row.wan, row.wan_name, row.network, row.network_name) || '-',
      enabled: row.enabled !== false,
      predefined: row.predefined === true || row.default === true || row.is_default === true,
      children: asArray(row.children).map((child, childIndex) => normalizeRow(child, childIndex, fallbackType)),
      raw: row
    };
    if (normalized.policy_type === 'nat' && normalized.action_key === 'unknown') {
      normalized.action = '转换';
      normalized.action_key = 'convert';
    }
    return normalized;
  }
  function countBy(rows, field) {
    const map = new Map();
    rows.forEach((row) => {
      const value = row[field];
      const list = Array.isArray(value) ? value : [value];
      list.map((item) => firstText(item)).filter(Boolean).forEach((text) => map.set(text, (map.get(text) || 0) + 1));
    });
    return [...map.entries()].sort((a, b) => b[1] - a[1]).map(([label, count]) => ({ value: normalizeKey(label), label, count }));
  }
  function buildFilters(rows, serverFilters = {}) {
    const clone = structuredCloneSafe(FALLBACK_FILTERS);
    const typeCounts = new Map();
    const actionCounts = new Map();
    rows.forEach((row) => {
      typeCounts.set(row.policy_type, (typeCounts.get(row.policy_type) || 0) + 1);
      actionCounts.set(row.action_key, (actionCounts.get(row.action_key) || 0) + 1);
    });
    clone.policy_type = clone.policy_type.map((item) => ({ ...item, count: item.value === 'all' ? rows.length : (typeCounts.get(item.value) || 0), disabled: item.value !== 'all' && (typeCounts.get(item.value) || 0) === 0 }));
    clone.action = clone.action.map((item) => ({ ...item, count: actionCounts.get(item.value) || 0, disabled: (actionCounts.get(item.value) || 0) === 0 }));
    clone.protocol = countBy(rows, 'protocol');
    clone.source = countBy(rows, 'source');
    clone.destination = countBy(rows, 'destination');
    clone.interface = countBy(rows, 'interface');
    Object.entries(serverFilters || {}).forEach(([key, value]) => {
      if (!Array.isArray(value) || !value.length) return;
      if (key === 'policy_type') {
        const counts = new Map();
        value.forEach((item) => {
          const raw = normalizeKey(item && (item.value || item.key || item.id || item.label));
          const routeKey = routeFamilyKey(raw);
          const mapped = routeKey || (raw.includes('port') ? 'port_forwarding' : raw.includes('route') ? 'pbr' : raw);
          counts.set(mapped, Math.max(counts.get(mapped) || 0, Number(item && item.count) || 0));
        });
        clone.policy_type = clone.policy_type.map((item) => ({ ...item, count: item.value === 'all' ? rows.length : (counts.get(item.value) || typeCounts.get(item.value) || 0), disabled: item.value !== 'all' && (counts.get(item.value) || typeCounts.get(item.value) || 0) === 0 }));
        return;
      }
      clone[key] = value;
    });
    return clone;
  }
  function unwrapData(result) {
    const data = result?.data || {};
    return data.data && typeof data.data === 'object' ? data.data : data;
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
    const response = await sessionFetch(url, {
      credentials: 'same-origin', cache: 'no-store', ...options,
      headers: authHeaders({ ...(options.body ? { 'Content-Type': 'application/json' } : {}), ...(options.headers || {}) })
    });
    const text = await response.text();
    let json = {};
    if (text) {
      try { json = JSON.parse(text); } catch (_) { throw new Error('后端返回了无效 JSON'); }
    }
    const payload = json?.data ?? json;
    if (!response.ok || json?.ok === false || payload?.ok === false) {
      const message = firstText(payload?.message, payload?.error?.message, payload?.error, json?.message, json?.error?.message, json?.error, `HTTP ${response.status}`);
      throw new Error(message);
    }
    return payload;
  }
  function optionList(value) {
    return asArray(value).map((item) => ({
      value: firstText(item?.value, item?.id, item?.name, item),
      label: firstText(item?.label, item?.name, item?.value, item?.id, item),
      raw: item && typeof item === 'object' ? item : { value: item }
    })).filter((item) => item.value);
  }
  function normalizeCatalog(data = {}) {
    const catalog = structuredCloneSafe(EMPTY_CATALOG);
    Object.keys(catalog).forEach((key) => { catalog[key] = optionList(data[key]); });
    return catalog;
  }
  /*
   * 读 sources.applications 的分页自述。后端一直在诚实上报 total / truncated，
   * 只是以前前端一个字段都没消费，于是用户面对 5873 个应用只看到 100 个候选，
   * 界面上还没有任何"这是截断视图"的提示。
   *
   * total 取不到时退回已加载条数，避免显示成「已加载 500 / 共 0」这种自相矛盾的话。
   * has_more 优先用后端算的；老二进制没这个键时才回落到「已加载 < 总数」推断，
   * 这样前端在新旧后端上都不会把末页当成还有下一页。
   */
  function applyAppCatalogMeta(catalogData = {}, query = '', offset = 0) {
    const source = catalogData?.sources?.applications || {};
    const returned = Number(source.returned);
    const loaded = offset + (Number.isFinite(returned) ? returned : (state.catalog.applications || []).length);
    const total = Number(source.total);
    const resolvedTotal = Number.isFinite(total) && total > 0 ? total : loaded;
    const hasMore = typeof source.has_more === 'boolean' ? source.has_more
      : (typeof source.truncated === 'boolean' ? source.truncated : loaded < resolvedTotal);
    state.appCatalog = {
      ...state.appCatalog,
      query,
      loaded,
      total: resolvedTotal,
      hasMore,
      loading: false,
      error: source.available === false ? firstText(source.reason) || '应用目录不可用' : ''
    };
  }
  function resetAppCatalogMeta() {
    state.appCatalog = { ...state.appCatalog, query: '', loaded: 0, total: 0, hasMore: false, loading: false, error: '' };
  }
  /*
   * 应用候选的服务端查询。offset=0 时替换候选列表（新搜索），offset>0 时追加（翻页）。
   *
   * 只请求 applications 这一路的数据，但 catalog 是个整体端点，返回的其他键这里
   * 一概不动 —— 覆盖 state.catalog 的其他候选源会把用户已选中的设备/网络标签抹掉。
   */
  async function loadApplications(query = '', offset = 0) {
    const seq = ++state.appCatalog.seq;
    state.appCatalog = { ...state.appCatalog, loading: true, error: '' };
    patchOverlays();
    const params = `app_limit=${APP_PAGE_SIZE}&app_offset=${offset}${query ? `&app_q=${encodeURIComponent(query)}` : ''}`;
    try {
      const result = await fetchApi('policy-catalog-apps', `${CATALOG_ENDPOINT}?${params}`);
      if (!mounted || seq !== state.appCatalog.seq) return;
      if (!result?.ok) throw new Error('应用目录读取失败');
      const catalogData = unwrapData(result);
      const page = optionList(catalogData.applications);
      /* 追加时按 value 去重：后端 ORDER BY 稳定（category sort_order, name, app_id），
         但并发翻页仍可能让同一页回来两次，重复的 value 会渲染出两行同名候选。 */
      if (offset > 0) {
        const seen = new Set((state.catalog.applications || []).map((item) => item.value));
        state.catalog.applications = [...(state.catalog.applications || []), ...page.filter((item) => !seen.has(item.value))];
      } else {
        state.catalog.applications = page;
      }
      applyAppCatalogMeta(catalogData, query, offset);
    } catch (error) {
      if (!mounted || seq !== state.appCatalog.seq) return;
      state.appCatalog = { ...state.appCatalog, loading: false, error: firstText(error?.message) || '应用目录读取失败' };
    }
    patchOverlays();
  }
  /*
   * network/wans 的每条记录里 `ip` 是接口地址、`public_ip` 才是真实出口：
   * wan2 走 CGNAT 时 ip=10.132.53.47 而 public_ip=39.154.0.61，端口转发要给
   * 用户看的是后者。按 name/id/ifname 建索引，因为 zone 的 members 与 catalog
   * 的 wans[].value 用的是 WAN 名（wan / wan2），不是 ifname。
   */
  function applyWanAddresses(settled) {
    if (settled?.status !== 'fulfilled' || !settled.value?.ok) {
      state.wanAddressState = 'error';
      return;
    }
    const data = unwrapData(settled.value);
    const list = asArray(data.wans || data);
    const map = {};
    list.forEach((item) => {
      if (!item || typeof item !== 'object') return;
      const entry = {
        public_ip: firstText(item.public_ip),
        ip: firstText(item.ip, item.ipaddr, item.address)
      };
      [item.name, item.id, item.ifname].forEach((key) => {
        const name = normalizeKey(key);
        if (name && !map[name]) map[name] = entry;
      });
    });
    state.wanAddresses = map;
    state.wanAddressState = list.length ? 'ready' : 'empty';
  }
  /*
   * PBR 出口候选。`asArray()` 已经认 items，但这里显式写出来是因为踩过一次坑：
   * 按 `tables` 取会得到 0 条，读起来像「没有任何路由表」，而实际是键名不同。
   */
  function applyRouteTables(settled) {
    if (settled?.status !== 'fulfilled' || !settled.value?.ok) {
      state.routeTables = [];
      state.routeTablesState = 'error';
      return;
    }
    const data = unwrapData(settled.value);
    const list = asArray(data.items || data.tables || data).filter((item) => item && typeof item === 'object');
    state.routeTables = list.map((item) => ({
      id: firstText(item.id, item.name),
      name: firstText(item.name, item.id),
      table_id: Number(item.table_id) || 0,
      role: firstText(item.role),
      enabled: item.enabled !== false
    })).filter((item) => item.id);
    state.routeTablesState = state.routeTables.length ? 'ready' : 'empty';
  }
  function applyZoneMembers(settled) {
    if (settled?.status !== 'fulfilled' || !settled.value?.ok) return;
    const data = unwrapData(settled.value);
    const map = {};
    asArray(data.zones || data).forEach((zone) => {
      if (!zone || typeof zone !== 'object') return;
      const id = firstText(zone.id, zone.name);
      if (!id) return;
      map[id] = asArray(zone.members).map((member) => firstText(member)).filter(Boolean);
    });
    state.zoneMembers = map;
  }
  /* 返回 [显示文本, 是否为真实地址]。取不到时不再说「后端未提供」—— 地址来自
     network/wans，读不到是本页请求或该 WAN 没拿到地址，不是后端没做。 */
  function wanAddressText(wanName) {
    if (normalizeKey(wanName) === 'all') return ['随所选 WAN 变化', false];
    const entry = state.wanAddresses[normalizeKey(wanName)];
    const address = entry ? firstText(entry.public_ip, entry.ip) : '';
    if (address) return [address, true];
    if (state.wanAddressState === 'idle') return ['读取中', false];
    if (state.wanAddressState === 'error') return ['WAN 地址读取失败', false];
    return ['该接口未获取到地址', false];
  }
  async function load() {
    const seq = ++state.seq;
    state.loading = true;
    state.error = '';
    patchPolicyView();
    try {
      const [policyResult, catalogResult, wanResult, tablesResult, zonesResult] = await Promise.allSettled([
        fetchApi('policy-table', `${ENDPOINT}?include_default=${state.showDefault ? 1 : 0}`),
        fetchApi('policy-catalog', `${CATALOG_ENDPOINT}?app_limit=${APP_PAGE_SIZE}&app_offset=0`),
        fetchApi('network-wans', WANS_ENDPOINT),
        fetchApi('routing-tables', ROUTING_TABLES_ENDPOINT),
        fetchApi('policy-zones', ZONES_ENDPOINT)
      ]);
      if (!mounted || seq !== state.seq) return;
      applyWanAddresses(wanResult);
      applyRouteTables(tablesResult);
      applyZoneMembers(zonesResult);
      if (policyResult.status !== 'fulfilled' || !policyResult.value?.ok) throw policyResult.reason || policyResult.value?.error || new Error('policy table unavailable');
      const result = policyResult.value;
      if (!result?.ok) throw result?.error || new Error('policy table unavailable');
      const data = unwrapData(result);
      const rawRows = asArray(data.rows || data.items || data.policies || data);
      const rows = rawRows.map((row, index) => normalizeRow(row, index));
      state.rows = rows;
      state.filters = buildFilters(rows, data.filters || data.facets);
      state.source = firstText(data.source, result.raw?.meta?.source) || 'policy-engine';
      state.capabilities = data.capabilities || {};
      if (catalogResult.status === 'fulfilled' && catalogResult.value?.ok) {
        const catalogData = unwrapData(catalogResult.value);
        state.catalog = normalizeCatalog(catalogData);
        state.catalogError = '';
        applyAppCatalogMeta(catalogData, '', 0);
        if (!Object.keys(state.capabilities).length && catalogData.capabilities) state.capabilities = catalogData.capabilities;
      } else {
        state.catalog = structuredCloneSafe(EMPTY_CATALOG);
        state.catalogError = '创建目录读取失败';
        resetAppCatalogMeta();
      }
      state.loading = false;
    } catch (error) {
      if (!mounted || seq !== state.seq) return;
      state.rows = [];
      state.filters = buildFilters([]);
      state.source = 'backend-gap';
      state.capabilities = {};
      state.error = '后端策略表聚合接口未就绪，当前不展示假数据；后端缺口已落 MD。';
      state.loading = false;
    }
    patchPolicyView();
  }
  function rowMatches(row) {
    if (!state.showDefault && row.predefined) return false;
    if (state.type !== 'all' && row.policy_type !== state.type) return false;
    const query = state.query.trim().toLowerCase();
    if (query) {
      const haystack = [row.name, row.type, row.action, row.protocol, row.source_zone, cellText(row.source), row.destination_zone, cellText(row.destination), row.destination_port, row.interface].join(' ').toLowerCase();
      if (!haystack.includes(query)) return false;
    }
    for (const key of ['action', 'protocol', 'source', 'destination', 'interface']) {
      const selected = state.selectedFilters[key];
      if (!selected || !selected.size) continue;
      const value = key === 'action' ? row.action_key : normalizeKey(cellText(row[key], ''));
      if (!selected.has(value)) return false;
    }
    return true;
  }
  function visibleRows() {
    return state.rows.filter(rowMatches);
  }
  function toggleSet(set, value) {
    if (set.has(value)) set.delete(value);
    else set.add(value);
  }
  function columnVisible(key) {
    /*
     * 展开列只在真的有可展开行时才出现。它的格子只有 `row.children?.length`
     * 为真时才渲染按钮，否则整列都是空的，却仍占着 46px —— 名称列因此被推离
     * 卡片左缘 46px（用户 2026-08-05：「名称列前方就不要留空了」）。
     * 实测 30.1 当前 42 行策略一个子行都没有，可展开按钮 0 个。
     */
    if (key === 'expand') return hasExpandableRows();
    return state.visibleColumns.has(key);
  }

  /* 当前可见数据里是否存在带子行的策略。 */
  function hasExpandableRows() {
    return visibleRows().some((row) => row.children?.length);
  }

  /*
   * 表头、colgroup 与每一行数据必须用**同一份**列集合。
   * 之前 renderTable() 与 renderRow() 各自调用 columnVisible()，而展开列的可见性
   * 取决于数据（hasExpandableRows()），两处求值时机一旦不同，表头 10 列、数据行
   * 11 格，整行数据右移一列 —— 实测出现过 thead 无 expand 而 tbody 有 expand。
   */
  function activeColumns() {
    return DEFAULT_COLUMNS.filter((column) => columnVisible(column.key));
  }
  /* Every column gets its declared pixel width except 名称, which takes the slack so
     a wide viewport does not leave a ragged gap at the right edge. Under fixed layout
     a percentage on the last flexible column is the reliable way to do that: `auto`
     on a <col> is not honoured consistently once the other columns are pinned. */
  function columnGroupMarkup(cols) {
    const fixedWidth = cols
      .filter((column) => column.key !== 'name')
      .reduce((sum, column) => sum + (column.min || 42), 0);
    return `<colgroup>${cols.map((column) => {
      if (column.key === 'name') {
        return `<col data-policy-col="name" style="width:calc(100% - ${fixedWidth}px);min-width:${column.min}px">`;
      }
      return `<col data-policy-col="${escapeHtml(column.key)}" style="width:${column.min || 42}px">`;
    }).join('')}</colgroup>`;
  }

  /* 当前列集合的宽度总和。表宽必须等于它，否则 fixed 布局改成平分列宽。
     展开列是动态的，所以这个值只能算，不能写死在 CSS 里。 */
  function tableMinWidth(cols) {
    return cols.reduce((sum, column) => sum + (column.min || 42), 0);
  }
  function renderStatus() {
    if (state.loading) return '正在读取策略表…';
    if (state.error) return state.error;
    return '';
  }

  /*
   * 表格工具栏里的搜索 / 筛选 / 创建。原先它们单独占一个页面级 `<header>`
   * （实测 58px，把卡片顶边压到 y=86），而操作对象就是下面这张表
   * —— 按 design.md 规则 15 收进 `.dwrt-kit-table-toolbar`。
   * data-* 钩子沿用原名，bindEvents() 不用改。
   */
  function tableActionsMarkup() {
    return `<div class="policy-table-actions">
      <label class="policy-search policy-search-main" data-dwrt-component="expand-search">${renderSearchIcon()}<input data-policy-search type="search" placeholder="搜索策略表" value="${escapeHtml(state.query)}"></label>
      <div class="policy-toolbar-actions">
        <button type="button" class="policy-filter-button" data-open-filter>${renderFilterIcon()}<span>筛选</span>${filterButtonCount()}</button>
        <button type="button" class="policy-create-button" data-open-create ${state.loading || state.capabilities.create !== true ? 'disabled' : ''}>${renderPlusIcon()}<span>${state.loading ? '正在读取能力' : '创建新策略'}</span></button>
      </div>
    </div>`;
  }
  function filterCount() {
    let count = 0;
    if (state.query.trim()) count += 1;
    if (!state.showDefault) count += 1;
    if (state.type !== 'all') count += 1;
    Object.values(state.selectedFilters).forEach((set) => { count += set.size; });
    return count;
  }
  function filterButtonCount() {
    const count = filterCount();
    return count ? `<span class="policy-count-badge">${count}</span>` : '';
  }
  function renderSearchIcon() {
    return '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><circle cx="11" cy="11" r="7"></circle><path d="m16.5 16.5 4 4"></path></svg>';
  }
  function renderFilterIcon() {
    return '<svg viewBox="0 0 20 20" fill="currentColor"><path d="M3 4.5A.5.5 0 0 1 3.5 4h13a.5.5 0 0 1 .39.812L12 10.925V15a.5.5 0 0 1-.276.447l-3 1.5A.5.5 0 0 1 8 16.5v-5.575L3.11 4.812A.5.5 0 0 1 3 4.5Z"></path></svg>';
  }
  function renderPlusIcon() {
    return '<svg viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M10 4v12M4 10h12"></path></svg>';
  }
  function renderFilterSection(title, key, items, type = 'checkbox') {
    const collapsed = state.collapsed.has(key);
    const controls = (items || []).map((item) => {
      const value = normalizeKey(item.value || item.label);
      const disabled = item.disabled ? ' disabled' : '';
      const checked = type === 'radio' ? (state.type === value ? ' checked' : '') : (state.selectedFilters[key]?.has(value) ? ' checked' : '');
      return `<label class="policy-filter-row${item.disabled ? ' is-disabled' : ''}">
        <input type="${type}" name="policy-${key}" data-filter-key="${escapeHtml(key)}" value="${escapeHtml(value)}"${checked}${disabled}>
        <span class="policy-control-dot"></span>
        <span class="policy-filter-label">${escapeHtml(item.label || item.value)}</span>
        <span class="policy-filter-count">${Number.isFinite(Number(item.count)) ? Number(item.count) : ''}</span>
      </label>`;
    }).join('') || '<div class="policy-empty-inline">暂无可用筛选项</div>';
    return `<section class="policy-filter-section${collapsed ? ' is-collapsed' : ''}" data-filter-section="${escapeHtml(key)}">
      <button class="policy-filter-section-head" type="button" data-toggle-section="${escapeHtml(key)}">
        <span>${escapeHtml(title)}</span>
        <svg viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="1.7"><path d="m5 8 5 5 5-5"></path></svg>
      </button>
      <div class="policy-filter-section-body">${controls}</div>
    </section>`;
  }
  function renderDrawer() {
    return `<aside class="policy-filter-drawer dwrt-kit-sheet dwrt-glass-card policy-stable-glass${state.drawerOpen ? ' is-open' : ''}" aria-hidden="${state.drawerOpen ? 'false' : 'true'}">
      <div class="policy-drawer-head dwrt-kit-sheet-header">
        <div><span>Filter</span><strong>筛选策略表</strong></div>
        <button class="policy-icon-button dwrt-kit-sheet-close" type="button" data-close-filter aria-label="关闭筛选">×</button>
      </div>
      <div class="policy-drawer-body dwrt-kit-sheet-body">
        <label class="policy-search policy-search-drawer">
          ${renderSearchIcon()}
          <input data-policy-search-drawer type="search" placeholder="搜索策略表" value="${escapeHtml(state.query)}">
        </label>
        <label class="policy-default-toggle">
          <input type="checkbox" data-show-default ${state.showDefault ? 'checked' : ''}>
          <span class="policy-control-box"></span>
          <span>查看默认策略 (${state.rows.filter((row) => row.predefined).length})</span>
        </label>
        ${renderFilterSection('策略类型', 'policy_type', state.filters.policy_type, 'radio')}
        ${renderFilterSection('操作', 'action', state.filters.action)}
        ${renderFilterSection('协议', 'protocol', state.filters.protocol)}
        ${renderFilterSection('源', 'source', state.filters.source)}
        ${renderFilterSection('目标', 'destination', state.filters.destination)}
        ${renderFilterSection('接口', 'interface', state.filters.interface)}
      </div>
      <footer class="policy-drawer-foot dwrt-kit-sheet-footer">
        <button type="button" class="policy-text-button" data-clear-filters ${filterCount() ? '' : 'disabled'}>清除筛选条件</button>
        <button type="button" class="policy-text-button" data-open-columns>自定义列</button>
      </footer>
    </aside>`;
  }
  function renderColumnsPanel() {
    if (!state.columnsOpen) return '';
    return `<div class="policy-popover policy-columns-popover dwrt-glass-card policy-stable-glass" data-columns-panel>
      <div class="policy-popover-head"><strong>自定义列</strong><button type="button" data-close-columns>×</button></div>
      <div class="policy-column-list">
        ${DEFAULT_COLUMNS.filter((column) => column.key !== 'expand').map((column) => `<label class="policy-filter-row"><input type="checkbox" data-column-toggle value="${escapeHtml(column.key)}" ${state.visibleColumns.has(column.key) ? 'checked' : ''}><span class="policy-control-box"></span><span>${escapeHtml(column.label)}</span></label>`).join('')}
      </div>
    </div>`;
  }
  function rawOptions(row = {}) {
    const envelope = row.raw && typeof row.raw === 'object' ? row.raw : {};
    const raw = envelope.raw && typeof envelope.raw === 'object' ? envelope.raw : envelope;
    const source = raw.raw && typeof raw.raw === 'object' ? raw.raw : raw;
    const options = source.options && typeof source.options === 'object' ? source.options : {};
    return { ...envelope, ...raw, ...source, ...options };
  }
  function rawValue(row, ...keys) {
    const raw = rawOptions(row);
    for (const key of keys) {
      const value = raw[key] ?? row?.[key];
      if (value !== undefined && value !== null && String(value).trim() !== '') return Array.isArray(value) ? value.join(' ') : value;
    }
    return '';
  }
  function writeTypes() {
    return new Set(asArray(state.capabilities.write_supported_policy_types).map(normalizeKey));
  }
  /* ACL 的可写子类型由后端能力位给出，当前只有 mac。之前这里连页签都硬编码
     disabled，等于把后端已经开放的能力也一起关掉了。 */
  function aclWriteTypes() {
    return asArray(state.capabilities.acl_write_supported_types).map(normalizeKey);
  }
  function aclPendingTypes() {
    return asArray(state.capabilities.acl_write_pending_types).map(normalizeKey);
  }
  function aclMacWritable() {
    return aclWriteTypes().includes('mac') && capabilityFor('acl', 'create');
  }
  /*
   * 时段与到期都以能力位为判据，不照抄注释：30.1 实测
   * acl_schedule_supported=true、acl_schedule_max_windows=1、
   * acl_schedule_weekdays_supported=true、acl_expires_supported=true。
   * 判据写成 !== false 会把"能力源没读到"也当成开放，所以这里只认 === true。
   */
  function aclScheduleSupported() {
    return state.capabilities.acl_schedule_supported === true;
  }
  function aclScheduleWeekdaysSupported() {
    return state.capabilities.acl_schedule_weekdays_supported === true;
  }
  function aclExpiresSupported() {
    return state.capabilities.acl_expires_supported === true;
  }
  /* 后端只渲染一个时间表达式，多窗口需要多条规则。上限从能力位取。 */
  function aclScheduleMaxWindows() {
    const value = Number(state.capabilities.acl_schedule_max_windows);
    return Number.isFinite(value) && value > 0 ? value : 1;
  }
  const ACL_PENDING_LABELS = {
    connection_limit: '连接数限制',
    app: '应用管控',
    url_access: 'URL 访问',
    terminal_limit: '终端限速'
  };
  /*
   * 未开放子类型的原因串只从 capabilities 取，不自己编。
   *
   * 主字段是 acl_write_pending_reasons 这个对象，四个子类型各一条；旧后端只有
   * acl_connection_limit_reason 一个平铺字段（恰好命中 `acl_${key}_reason`），
   * 所以回退必须保留 —— 否则新前端配旧 webd 会把 connection_limit 现有的原因串
   * 一起丢掉。
   */
  function aclPendingReason(type) {
    const key = normalizeKey(type);
    const bag = state.capabilities.acl_write_pending_reasons;
    const fromBag = bag && typeof bag === 'object' && !Array.isArray(bag)
      ? firstText(bag[key], bag[type])
      : '';
    return firstText(fromBag, state.capabilities[`acl_${key}_reason`], state.capabilities[`${key}_reason`]);
  }
  /*
   * 后端给的原因串是机器可读的 key，直接显示等于让用户读英文枚举。这里只做
   * key → 中文的展示映射：能力位没给串时仍然不显示任何解释（不自己编原因），
   * 给了但不在表里的按原样显示，避免映射表落后于后端时把信息吞掉。
   *
   * 三种成因必须能区分开：入口未开放（后端做了但写不进）、可存但不生效、
   * 依赖缺失。connection_limit 尤其不能读成"随便存无所谓"—— 一条启用的规则
   * 会让整份 netctl ruleset 应用失败。
   */
  const ACL_PENDING_REASON_TEXT = {
    dataplane_ready_blocked_by_mac_only_write_gate: '后端已实现，但写入入口暂只开放 MAC 类型',
    persisted_without_dataplane: '可以保存，但当前不会生效',
    nft_connlimit_kmod_missing_blocks_whole_ruleset: '依赖的内核模块未随固件安装，暂不可用；启用后整份防火墙规则会应用失败',
    /* 旧 webd 的取值。30.1 实测当前仍返回这一条，新 webd 上线后才换成上面那条；
       两条都留着，否则升级前后必有一段时间显示英文枚举。 */
    nft_connlimit_expression_unavailable: '依赖的 nftables connlimit 表达式不可用，暂不可用'
  };
  function aclPendingReasonText(type) {
    const reason = aclPendingReason(type);
    if (!reason) return '';
    return ACL_PENDING_REASON_TEXT[normalizeKey(reason)] || reason;
  }
  /*
   * 终端限速与「终端联网控制」页的 client_rate_limit 是两套并存的东西，不是同一
   * 功能的两个名字。只说"终端限速未开放"会让用户以为限速整个不能用，所以把后端
   * 给的可写替代路径一并指出来。替代路径同样只从能力位取。
   */
  function aclPendingAlternativeText(type) {
    if (normalizeKey(type) !== 'terminal_limit') return '';
    const alternative = firstText(state.capabilities.acl_terminal_limit_writable_alternative);
    if (!alternative) return '';
    return '限速功能本身可用，可在「终端联网控制」页为终端设置限速';
  }
  function capabilityFor(type, action) {
    const key = normalizeKey(type);
    const prefixes = { firewall: 'firewall_rule', port_forwarding: 'port_forwarding', dns: 'dns_record', nat: 'nat', static_route: 'static_route', qos: 'qos_sqm', pbr: 'pbr' };
    const explicit = state.capabilities[`${prefixes[key] || key}_${action}`];
    if (typeof explicit === 'boolean') return explicit;
    return writeTypes().has(key) && state.capabilities[action] !== false;
  }
  const CREATE_TYPES = [
    { value: 'firewall', label: '防火墙' },
    { value: 'route', label: '路由' },
    { value: 'qos', label: 'QoS' },
    { value: 'nat', label: 'NAT' },
    { value: 'dns', label: 'DNS' },
    { value: 'acl', label: 'ACL' },
    { value: 'port_forwarding', label: '端口转发' }
  ];
  const SERVICE_PORTS = [
    ['', '自定义'], ['179', 'BGP · 179'], ['68', 'DHCP Client · 68'], ['67', 'DHCP Server · 67'],
    ['53', 'DNS · 53'], ['853', 'DNS-TLS · 853'], ['21', 'FTP · 21'], ['80', 'HTTP · 80'],
    ['443', 'HTTPS · 443'], ['500', 'IKE · 500'], ['123', 'NTP · 123'], ['1194', 'OpenVPN · 1194'],
    ['3389', 'RDP · 3389'], ['554', 'RTSP · 554'], ['5060', 'SIP · 5060'], ['445', 'SMB · 445'],
    ['25', 'SMTP · 25'], ['161', 'SNMP · 161'], ['22', 'SSH · 22'], ['514', 'Syslog · 514'],
    ['23', 'Telnet · 23'], ['51820', 'WireGuard · 51820']
  ];
  const CUSTOM_PROTOCOLS = [['ah','AH'],['dccp','DCCP'],['esp','ESP'],['gre','GRE'],['icmp','ICMP'],['icmpv6','ICMPv6'],['igmp','IGMP'],['ipip','IPIP'],['ipv6','IPv6'],['l2tp','L2TP'],['ospf','OSPF'],['pim','PIM'],['sctp','SCTP'],['vrrp','VRRP']];
  function firstCatalogValue(key, fallback = '') {
    return state.catalog[key]?.[0]?.value || fallback;
  }
  function ipv4WanOptions() {
    return (state.catalog.wans || []).filter((item) => !/(^|[^a-z])dhcpv6([^a-z]|$)|\bwan6\b/i.test(`${item.value} ${item.label}`));
  }
  /*
   * PBR 源维度的能力位。按 pbr_* 渲染，**不要**看 objects_crud —— 后者管的是
   * 复合对象目录（仍为 false），跟「按接口/zone 分流」是两条路。
   */
  function pbrSourceKinds() {
    const declared = asArray(state.capabilities.pbr_source_kinds).map(normalizeKey).filter(Boolean);
    if (!state.capabilities.pbr_source_kinds_supported) return ['object'];
    const kinds = declared.length ? declared : ['object', 'interface', 'zone', 'network'];
    return kinds.filter((kind) => {
      if (kind === 'interface') return state.capabilities.pbr_source_interface !== false;
      if (kind === 'zone') return state.capabilities.pbr_source_zone !== false;
      return ['object', 'network'].includes(kind);
    });
  }
  function pbrSourceKindOptions() {
    const labels = { object: 'IP 组 / 对象', interface: '接口', zone: '区域', network: '网络' };
    return pbrSourceKinds().map((kind) => [kind, labels[kind] || kind]);
  }
  function pbrPinWanSupported() {
    return state.capabilities.pbr_pin_wan === true;
  }
  /* 后端只在 interface/zone/network 源上接受 pin_wan（object 源直接报错）。
     作用域串也从能力位读，不自己判断。 */
  function pbrPinWanAllowed(kind = state.draft.source_kind) {
    if (!pbrPinWanSupported()) return false;
    const scope = normalizeKey(state.capabilities.pbr_pin_wan_scope);
    const key = normalizeKey(kind) || 'object';
    if (key === 'object') return false;
    if (!scope) return true;
    return scope.includes(key);
  }
  /* 目标 WAN 掉线后的语义直接来自能力位，不在前端编造「会自动回落」。 */
  function pbrPinWanConsequence() {
    const raw = normalizeKey(state.capabilities.pbr_pin_wan_on_target_wan_down);
    if (raw.includes('blackhole') || raw.includes('stays_pinned'))
      return '目标 WAN 掉线后不会自动回落到其他线路：该来源的流量会一直断，直到这条 WAN 恢复。';
    if (raw) return `目标 WAN 掉线时的行为：${firstText(state.capabilities.pbr_pin_wan_on_target_wan_down)}`;
    return '';
  }
  function pbrSourceRefCatalogKey(kind = state.draft.source_kind) {
    const key = normalizeKey(kind);
    if (key === 'zone') return 'source_zones';
    if (key === 'network') return 'networks';
    return 'interfaces';
  }
  /* zone 源的候选：catalog.source_zones 去掉 any（源 = 任何区域没有意义，
     那是 source_kind=object + any 的语义），并把成员拼进标签，
     因为 dw_lan2 这种 id 本身看不出它对应 lan2。 */
  function pbrSourceRefOptions(kind = state.draft.source_kind) {
    const key = normalizeKey(kind);
    if (key === 'zone') {
      return (state.catalog.source_zones || [])
        .filter((item) => normalizeKey(item.value) !== 'any')
        .map((item) => {
          const members = state.zoneMembers[item.value] || [];
          const label = firstText(item.label, item.value);
          return { value: item.value, label: members.length ? `${label} · ${members.join(', ')}` : label };
        });
    }
    const list = state.catalog[pbrSourceRefCatalogKey(key)] || [];
    /* 出口口不该当入口源：把 WAN 排掉，留下 LAN 侧网络/接口。 */
    const wanNames = new Set((state.catalog.wans || []).map((item) => normalizeKey(item.value)));
    return list.filter((item) => !wanNames.has(normalizeKey(item.value)) && normalizeKey(item.value) !== 'loopback');
  }
  /* 出口候选只来自 route_table 账本。空列表意味着一条规则也建不成，
     这时给出的是拦阻理由，而不是一个能选但注定失败的下拉。 */
  function pbrTargetOptions() {
    return state.routeTables
      .filter((item) => item.enabled)
      .map((item) => ({
        value: item.id,
        label: item.table_id ? `${item.name} · 表 ${item.table_id}` : item.name
      }));
  }
  function editorType(type = state.draft.policy_type) {
    return ['pbr', 'static_route'].includes(type) ? 'route' : type;
  }
  function typeCanCreate(type) {
    if (type === 'route') return capabilityFor('pbr', 'create') || capabilityFor('static_route', 'create');
    /* ACL 不硬编码关闭：后端 acl_write_supported_types 含 mac 时这一项可选，
       选中后本页直接给出可保存的 MAC 表单（见 renderAclFields）。 */
    if (type === 'acl') return aclMacWritable();
    return capabilityFor(type, 'create');
  }
  function newDraft(type = 'firewall') {
    const firstWan = ipv4WanOptions()[0]?.value || state.catalog.wans[0]?.value || 'wan';
    const firstInterface = state.catalog.interfaces.find((item) => !['loopback', 'lan'].includes(item.value))?.value || firstWan;
    const common = { policy_type: type, name: '', enabled: true };
    if (type === 'firewall') return { ...common, action: 'block', protocol: 'all', custom_protocol: 'esp', source_zone: 'lan', destination_zone: 'wan', source_type: 'any', destination_type: 'any', source_match: 'specific', destination_match: 'specific', source_ip: '', destination_ip: '', source_port_mode: 'any', destination_port_mode: 'any', source_port: '', destination_port: '', source_port_service: '', destination_port_service: '', source_devices: [], source_networks: [], source_identities: [], destination_app_mode: 'specific', destination_applications: [], destination_regions: [], source_match_opposite: false, destination_match_opposite: false, source_match_mac: false, source_port_opposite: false, destination_port_opposite: false, family: '', connection_state: 'all', connection_states: [], match_ipsec: false, ipsec_mode: 'encrypted', syslog: false, schedule_mode: 'always', schedule_start: '09:00', schedule_end: '12:00', schedule_date: '', schedule_date_end: '', schedule_weekdays: [], schedule_all_day: false, description: '' };
    if (type === 'port_forwarding') return { ...common, protocol: 'tcp_udp', source_zone: firstWan, destination_zone: 'lan', external_port: '', internal_ip: '', internal_devices: [], internal_port: '', source_mode: 'any', source_ip: '', family: 'ipv4', syslog: false };
    if (type === 'dns') return { ...common, record_type: 'a', domain: '', ip: '', target: '', ttl_mode: 'auto', ttl: 300, mail_server: '', priority: 0, text: '', server: '', service: '', dns_protocol: '', port: '', weight: 0, dns_server: '' };
    if (type === 'nat') return { ...common, target: 'masquerade', interface: firstWan, protocol: 'all', custom_protocol: 'esp', source_type: 'any', destination_type: 'any', source_ip: '', destination_ip: '', source_port_mode: 'any', destination_port_mode: 'any', source_port: '', destination_port: '', translated_ip_mode: 'primary', translated_ip: '', translate_port: false, translated_port: '', family: 'ipv4', syslog: false, exclude: false };
    if (type === 'static_route') return { ...common, route_mode: 'static', family: 'ipv4', destination: '', gateway_mode: 'next_hop', gateway: '', interface: firstInterface, table: 'main', metric: 0, mtu: 1500, route_kind: 'unicast', source: '' };
    if (type === 'qos') return { ...common, qos_behavior: 'limit', interface: firstInterface, download_enabled: false, upload_enabled: false, download: 10, upload: 10, download_unit: 'mbps', upload_unit: 'mbps', download_burst: 'off', upload_burst: 'off', source_type: 'any', source_devices: [], source_networks: [], destination_type: 'any', destination_ip: '', destination_domain: '', destination_applications: [], destination_regions: [], destination_port_mode: 'any', destination_port: '', schedule_mode: 'always', qdisc: 'cake', script: 'piece_of_cake.qos', linklayer: 'none', overhead: '' };
    if (type === 'pbr') {
      /* 出口默认取账本里的第一张路由表，而不是 catalog 的第一条 WAN：
         wan3/wan4 在 catalog 里有，但 route_table 里没有对应行，
         默认成它会让表单一开就带着一个提交必失败的 target。 */
      const firstTable = pbrTargetOptions()[0]?.value || '';
      return { ...common, route_mode: 'policy', interface: firstTable, kill_switch: true, source_kind: 'object', source_ref: '', pin_wan: false, source_type: 'any', source_items: [], destination_type: 'any', destination: 'any', destination_regions: [], protocol: 'all', ports: 'any', action: 'route_table', target: firstTable, route_table: firstTable, priority: 1000, schedule_mode: 'always', comment: '' };
    }
    /*
     * ACL 草稿按后端 webd_policy_acl_build_rule() 的字段来：acl_type=mac、
     * mac、action=deny（唯一支持的动作）、schedule（always 或单窗口）、
     * expires（绝对 unix 秒，0=永不）。enabled 默认 true —— 之前是 false，
     * 那是"本页不能写"时代的残留，会让新建的规则一落库就是停用的。
     */
    if (type === 'acl') return {
      ...common,
      acl_type: 'mac',
      action: 'deny',
      mac: '',
      terminal_name: '',
      priority: 1000,
      acl_schedule_mode: 'always',
      acl_schedule_start: '18:00',
      acl_schedule_end: '22:00',
      acl_schedule_weekdays: [],
      acl_expires_mode: 'never',
      acl_expires_at: ''
    };
    return common;
  }
  function draftFromRow(row) {
    const type = row.policy_type;
    const draft = newDraft(type);
    draft.name = row.name;
    draft.enabled = row.enabled;
    if (type === 'firewall') {
      const sourceIp = rawValue(row, 'src_ip');
      const destinationIp = rawValue(row, 'dest_ip');
      const sourcePort = rawValue(row, 'src_port');
      const destinationPort = rawValue(row, 'dest_port');
      return { ...draft, action: row.action_key, protocol: rawValue(row, 'proto', 'protocol') || 'all', source_zone: rawValue(row, 'src', 'source_zone') || 'lan', destination_zone: rawValue(row, 'dest', 'destination_zone') || 'wan', source_type: sourceIp ? 'ip' : 'any', destination_type: destinationIp ? 'ip' : 'any', source_ip: sourceIp, destination_ip: destinationIp, source_port_mode: sourcePort ? 'specific' : 'any', destination_port_mode: destinationPort ? 'specific' : 'any', source_port: sourcePort, destination_port: destinationPort, family: rawValue(row, 'family') };
    }
    if (type === 'port_forwarding') { const sourceIp=rawValue(row,'src_ip'); return { ...draft, protocol: rawValue(row, 'proto') || 'tcp_udp', source_zone: rawValue(row, 'src') || 'wan', destination_zone: rawValue(row, 'dest') || 'lan', external_port: rawValue(row, 'src_dport'), internal_ip: rawValue(row, 'dest_ip'), internal_port: rawValue(row, 'dest_port'), source_mode: sourceIp ? 'restricted' : 'any', source_ip: sourceIp, family: rawValue(row, 'family') || 'ipv4' }; }
    if (type === 'dns') {
      const sectionType = rawValue(row, 'section_type') || 'domain';
      const ip = rawValue(row, 'ip');
      return { ...draft, record_type: sectionType === 'cname' ? 'cname' : String(ip).includes(':') ? 'aaaa' : 'a', domain: rawValue(row, sectionType === 'cname' ? 'cname' : 'name', 'domain'), ip, target: rawValue(row, 'target') };
    }
    if (type === 'nat') { const sourcePort=rawValue(row,'src_port'), destinationPort=rawValue(row,'dest_port'), translatedIp=rawValue(row,'snat_ip'); return { ...draft, target: String(rawValue(row, 'target') || 'masquerade').toLowerCase(), protocol: rawValue(row, 'proto') || 'all', interface: rawValue(row, 'dest') || firstCatalogValue('wans','wan'), source_type: rawValue(row,'src_ip') ? 'ip' : 'any', destination_type: rawValue(row,'dest_ip') ? 'ip' : 'any', source_ip: rawValue(row, 'src_ip'), destination_ip: rawValue(row, 'dest_ip'), source_port_mode: sourcePort ? 'specific' : 'any', destination_port_mode: destinationPort ? 'specific' : 'any', source_port: sourcePort, destination_port: destinationPort, translated_ip_mode: translatedIp ? 'specific' : 'primary', translated_ip: translatedIp, translate_port: Boolean(rawValue(row,'snat_port')), translated_port: rawValue(row, 'snat_port'), family: rawValue(row, 'family') || 'ipv4' }; }
    if (type === 'static_route') return { ...draft, family: rawValue(row, 'section_type') === 'route6' ? 'ipv6' : (rawValue(row, 'family') || 'ipv4'), destination: rawValue(row, 'target', 'destination'), gateway: rawValue(row, 'gateway'), interface: rawValue(row, 'interface'), table: rawValue(row, 'table') || 'main', metric: Number(rawValue(row, 'metric')) || 0, mtu: Number(rawValue(row, 'mtu')) || 1500, route_kind: rawValue(row, 'type') || 'unicast', source: rawValue(row, 'source') };
    if (type === 'qos') { const download=Number(rawValue(row,'download'))||0, upload=Number(rawValue(row,'upload'))||0; return { ...draft, name: rawValue(row, 'name'), interface: rawValue(row, 'interface'), download_enabled: download>0, upload_enabled: upload>0, download: download>=1000 ? download/1000 : (download||10), upload: upload>=1000 ? upload/1000 : (upload||10), download_unit: download>=1000?'mbps':'kbps', upload_unit: upload>=1000?'mbps':'kbps', qdisc: rawValue(row, 'qdisc') || 'cake', script: rawValue(row, 'script') || 'piece_of_cake.qos', linklayer: rawValue(row, 'linklayer') || 'none', overhead: rawValue(row, 'overhead') }; }
    if (type === 'pbr') {
      const target=rawValue(row,'route_table','table','target')||pbrTargetOptions()[0]?.value||'';
      const destination=rawValue(row,'dest_object','destination')||'any';
      /* source_kind 缺省是 object，跟后端默认一致。接口/zone/network 规则的
         source_object 是空的，回填时不能把它读成 IP 组。 */
      const sourceKind=normalizeKey(rawValue(row,'source_kind'))||'object';
      const sourceRef=rawValue(row,'source_ref');
      const source=rawValue(row,'source_object')||'any';
      const isObject=sourceKind==='object'||!sourceRef;
      return { ...draft, interface: target, source_kind: isObject?'object':sourceKind, source_ref: isObject?'':sourceRef, pin_wan: rawValue(row,'pin_wan')===true||String(rawValue(row,'pin_wan'))==='true'||String(rawValue(row,'pin_wan'))==='1', source_type: isObject&&source!=='any'?'items':'any', source_items: isObject&&source!=='any'?[source]:[], destination_type: destination==='any'?'any':'ip', destination, protocol: rawValue(row, 'proto', 'protocol') || 'all', ports: rawValue(row, 'ports') || 'any', action: rawValue(row, 'action') || 'route_table', target, route_table: target, priority: Number(rawValue(row, 'priority')) || 1000, schedule_mode: 'always', comment: rawValue(row, 'comment') };
    }
    /*
     * ACL 回填：后端回读给的是 mac / mode / schedule / expires / terminal_name，
     * schedule 是 TEXT（"always" 或单窗口 JSON），expires 是绝对秒。
     * 不回填就等于用一份空草稿覆盖已有规则 —— MAC 会被清空并被后端拒绝，
     * 或者更糟，时段被悄悄改回始终生效。
     */
    if (type === 'acl') {
      const parsed = aclScheduleFromText(rawValue(row, 'schedule'));
      const expires = Number(rawValue(row, 'expires')) || 0;
      return {
        ...draft,
        acl_type: 'mac',
        mac: rawValue(row, 'mac', 'source'),
        terminal_name: rawValue(row, 'terminal_name'),
        priority: Number(rawValue(row, 'priority')) || 1000,
        acl_schedule_mode: parsed.mode,
        acl_schedule_start: parsed.start || draft.acl_schedule_start,
        acl_schedule_end: parsed.end || draft.acl_schedule_end,
        acl_schedule_weekdays: parsed.weekdays,
        acl_expires_mode: expires > 0 ? 'at' : 'never',
        acl_expires_at: expires > 0 ? aclExpiresInputValue(expires) : ''
      };
    }
    return draft;
  }
  /* 把存储里的 schedule 文本读回控件状态。解析不出来就退回"始终生效"，
     用户提交前还会在这一屏看到实际选中的是什么。 */
  function aclScheduleFromText(value) {
    const fallback = { mode: 'always', start: '', end: '', weekdays: [] };
    const text = String(value || '').trim();
    if (!text || text === 'always' || text[0] !== '[') return fallback;
    let parsed;
    try { parsed = JSON.parse(text); } catch (error) { return fallback; }
    if (!Array.isArray(parsed) || !parsed.length || typeof parsed[0] !== 'object' || !parsed[0]) return fallback;
    const entry = parsed[0];
    const start = firstText(entry.start_time);
    const end = firstText(entry.end_time);
    if (!start || !end) return fallback;
    return {
      mode: 'window',
      start,
      end,
      weekdays: asArray(entry.weekdays).map((item) => String(Number(item))).filter((item) => /^[0-6]$/.test(item))
    };
  }
  /* datetime-local 要的是本地时间的 YYYY-MM-DDTHH:MM，不能直接截 ISO 字符串
     （那是 UTC，会把时刻整体挪走）。 */
  function aclExpiresInputValue(seconds) {
    const date = new Date(Number(seconds) * 1000);
    if (!Number.isFinite(date.getTime())) return '';
    const pad = (value) => String(value).padStart(2, '0');
    return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}T${pad(date.getHours())}:${pad(date.getMinutes())}`;
  }
  function formField(label, control, wide = false) {
    return `<label class="policy-form-field${wide ? ' is-wide' : ''}"><span>${escapeHtml(label)}</span>${control}</label>`;
  }
  function formInput(name, value, placeholder = '', type = 'text', list = '') {
    return `<input type="${type}" data-policy-draft="${name}" value="${escapeHtml(value ?? '')}" placeholder="${escapeHtml(placeholder)}"${list ? ` list="${escapeHtml(list)}"` : ''}>`;
  }
  function formSelect(name, value, options) {
    const normalized = options.map((item) => ({ key: Array.isArray(item) ? item[0] : item.value, label: Array.isArray(item) ? item[1] : item.label }));
    if (value !== undefined && value !== null && String(value) && !normalized.some((item) => String(item.key) === String(value))) normalized.push({ key: value, label: value });
    return `<select data-policy-draft="${name}">${normalized.map((item) => `<option value="${escapeHtml(item.key)}" ${String(value) === String(item.key) ? 'selected' : ''}>${escapeHtml(item.label)}</option>`).join('')}</select>`;
  }
  function formDatalist(id, options) {
    return `<datalist id="${id}">${options.map((item) => `<option value="${escapeHtml(item.value)}">${escapeHtml(item.label)}</option>`).join('')}</datalist>`;
  }
  function zoneOptions(key, current) {
    const values = (state.catalog[key].length ? [...state.catalog[key]] : [{ value: 'lan', label: '内部' }, { value: 'wan', label: '外部' }]).filter((item) => normalizeKey(item.value) !== 'any');
    if (key === 'destination_zones' && !values.some((item) => normalizeKey(item.value) === 'gateway')) values.splice(Math.min(2, values.length), 0, { value: 'gateway', label: 'Gateway' });
    if (current && !values.some((item) => item.value === current)) return [...values, { value: current, label: current }];
    return values;
  }
  function section(title, body, className = '') {
    return `<section class="policy-editor-section ${className}">${title ? `<h3>${escapeHtml(title)}</h3>` : ''}<div class="policy-editor-section-body">${body}</div></section>`;
  }
  function editorField(label, control, hint = '') {
    return `<label class="policy-editor-field"><span>${escapeHtml(label)}</span>${control}${hint ? `<small>${escapeHtml(hint)}</small>` : ''}</label>`;
  }
  function radioGroup(field, value, options, label = field) {
    return `<div class="policy-choice-row" role="radiogroup" aria-label="${escapeHtml(label)}">${options.map(([key, text, disabled]) => `<label class="policy-choice${disabled ? ' is-disabled' : ''}"><input type="radio" name="policy-${escapeHtml(field)}" data-policy-radio="${escapeHtml(field)}" value="${escapeHtml(key)}" ${String(value) === String(key) ? 'checked' : ''} ${disabled ? 'disabled' : ''}><i></i><span>${escapeHtml(text)}</span></label>`).join('')}</div>`;
  }
  function editorCheck(field, checked, label, hint = '', disabled = false) {
    return `<label class="policy-editor-check${disabled ? ' is-disabled' : ''}"><input type="checkbox" data-policy-check="${escapeHtml(field)}" ${checked ? 'checked' : ''} ${disabled ? 'disabled' : ''}><i></i><span><strong>${escapeHtml(label)}</strong>${hint ? `<small>${escapeHtml(hint)}</small>` : ''}</span></label>`;
  }
  function editorSelect(field, value, options) {
    return formSelect(field, value, options);
  }
  function editorInput(field, value, placeholder = '', type = 'text') {
    return formInput(field, value, placeholder, type);
  }
  function arrayValue(field) {
    return Array.isArray(state.draft[field]) ? state.draft[field] : [];
  }
  /*
   * 应用候选走服务端搜索/分页，其余候选源仍在本地过滤已渲染的行。
   * 区别的理由是数据量：devices/objects/regions 都是几十条，全量在手；
   * applications 有 5873 条，单页上限 500，本地过滤只会过滤已取回的那部分，
   * 用户搜一个不在首页里的应用会得到空结果，看起来像"这个应用不存在"。
   */
  function isRemoteCatalogKey(catalogKey) {
    return catalogKey === 'applications';
  }
  /* 截断状态与 total 的可见呈现。库里有多少、当前取回多少，都要写在界面上。 */
  function catalogPickerFooter(field, catalogKey, optionCount) {
    if (!isRemoteCatalogKey(catalogKey)) {
      return optionCount ? `<button type="button" data-policy-pick-all="${escapeHtml(field)}" data-catalog-key="${escapeHtml(catalogKey)}">全选</button>` : '';
    }
    const meta = state.appCatalog;
    const scope = meta.query ? `匹配「${meta.query}」` : '全部应用';
    const counts = meta.total > meta.loaded
      ? `${scope} ${meta.total} 个，已加载 ${meta.loaded} 个`
      : `${scope} ${meta.total} 个，已全部加载`;
    const note = meta.error ? escapeHtml(meta.error)
      : meta.loading ? '正在读取应用目录…'
      : escapeHtml(counts);
    /* 「全选」在截断视图下只能选中已加载的部分，所以换个说法，不谎称选中了全库。 */
    const pickAllLabel = meta.hasMore ? '全选已加载' : '全选';
    /*
     * 用 <footer> 而不是 <div>：`.policy-object-menu > div` 带
     * `max-height:230px; overflow:auto`（那是候选列表的滚动容器），
     * `> div > label` 又有整套行样式，用 div 会让这一条也变成滚动区并串样式。
     */
    return `<footer class="policy-picker-foot"><small data-policy-picker-meta="${escapeHtml(catalogKey)}">${note}</small>${meta.hasMore && !meta.loading ? `<button type="button" data-policy-pick-more="${escapeHtml(catalogKey)}">加载更多</button>` : ''}${optionCount ? `<button type="button" data-policy-pick-all="${escapeHtml(field)}" data-catalog-key="${escapeHtml(catalogKey)}">${pickAllLabel}</button>` : ''}</footer>`;
  }
  function catalogPicker(field, catalogKey, label, emptyText = '暂无可用对象', emptyAction = '') {
    const selected = arrayValue(field);
    const options = state.catalog[catalogKey] || [];
    const open = state.pickerOpen === field;
    const remote = isRemoteCatalogKey(catalogKey);
    const summary = selected.length ? selected.map((value) => options.find((item) => item.value === value)?.label || value).join('、') : label;
    /*
     * 服务端搜索时输入框的值必须由脚本提供：patchOverlays() 会整段换掉抽屉正文，
     * 靠 DOM 自己保存的值会在每次重绘后被清空，用户打一个字就被吞掉。
     *
     * 这里读 appSearchQuery（用户正在打的原文）而不是 state.appCatalog.query
     * （已发出去那次查询的词）：防抖窗口内 loadApplications() 会先重绘一次显示
     * "正在读取"，此时若回填已提交的词，刚敲进去的字符会被抹掉。
     */
    const searchValue = remote ? appSearchQuery : '';
    const empty = remote && state.appCatalog.query ? `未找到匹配「${state.appCatalog.query}」的应用` : emptyText;
    /*
     * 空态给下一步，而不是只报告“没有数据”。地区目录空是因为还没人建 country
     * 对象，用户看不出这一点，会当成后端缺失（本页原文案正是这么被误读的）。
     */
    const emptyAside = emptyAction && !(remote && state.appCatalog.query)
      ? `<button type="button" class="policy-picker-empty-action" data-policy-goto-objects>${escapeHtml(emptyAction)}</button>`
      : '';
    const rows = options.length
      ? options.map((item) => `<label><input type="checkbox" data-policy-pick="${escapeHtml(field)}" value="${escapeHtml(item.value)}" ${selected.includes(item.value) ? 'checked' : ''}><i></i><span><strong>${escapeHtml(item.label)}</strong>${firstText(item.raw?.mac, item.raw?.address, item.raw?.subnet) ? `<small>${escapeHtml(firstText(item.raw?.mac, item.raw?.address, item.raw?.subnet))}</small>` : ''}</span></label>`).join('')
      : `<p>${escapeHtml(state.appCatalog.loading && remote ? '正在读取应用目录…' : empty)}${emptyAside}</p>`;
    const menu = `<div class="policy-object-menu"><label class="policy-object-search">${renderSearchIcon()}<input type="search" data-policy-picker-search ${remote ? `data-policy-picker-remote="${escapeHtml(catalogKey)}"` : ''} placeholder="${escapeHtml(remote ? '搜索应用（服务端查询）' : '搜索')}" value="${escapeHtml(searchValue)}"></label><div>${rows}</div>${catalogPickerFooter(field, catalogKey, options.length)}</div>`;
    return `<div class="policy-object-picker"><button type="button" data-policy-picker="${escapeHtml(field)}"><span>${escapeHtml(summary)}</span><b>${selected.length || ''}</b></button>${open ? menu : ''}</div>`;
  }
  function bulkEntry(field, placeholder) {
    const bulk = state.bulkInputs.has(field);
    return `<div class="policy-entry"><div>${bulk ? `<textarea data-policy-draft="${escapeHtml(field)}" placeholder="${escapeHtml(placeholder)}，每行一个">${escapeHtml(state.draft[field] || '')}</textarea>` : editorInput(field, state.draft[field], placeholder)}<button type="button" data-policy-bulk="${escapeHtml(field)}">${bulk ? '单项输入' : '添加多个'}</button></div></div>`;
  }
  function portEditor(prefix) {
    const modeField = `${prefix}_port_mode`;
    const portField = `${prefix}_port`;
    const serviceField = `${prefix}_port_service`;
    const oppositeField = `${prefix}_port_opposite`;
    const mode = state.draft[modeField] || 'any';
    return `<div class="policy-subfield"><span>端口</span>${radioGroup(modeField, mode, [['any','任何'],['specific','特定'],['list','列表']], `${prefix}端口`)}${mode === 'specific' ? `<div class="policy-port-specific">${editorSelect(serviceField, state.draft[serviceField] || '', SERVICE_PORTS)}${editorInput(portField, state.draft[portField], '例如 1-10,11')}</div>` : mode === 'list' ? catalogPicker(portField, 'objects', '选择端口列表', '尚无端口列表对象') : ''}${mode !== 'any' ? editorCheck(oppositeField, Boolean(state.draft[oppositeField]), '反向匹配端口') : ''}</div>`;
  }
  function scheduleEditor() {
    const d = state.draft;
    const mode = d.schedule_mode || 'always';
    let detail = '';
    if (mode === 'daily') detail = `<div class="policy-time-grid">${editorField('开始时间', editorInput('schedule_start', d.schedule_start, '', 'time'))}${editorField('结束时间', editorInput('schedule_end', d.schedule_end, '', 'time'))}</div>`;
    if (mode === 'weekly' || mode === 'custom') detail = `${mode === 'custom' ? `<div class="policy-time-grid">${editorField('开始日期', editorInput('schedule_date', d.schedule_date, '', 'date'))}${editorField('结束日期', editorInput('schedule_date_end', d.schedule_date_end, '', 'date'))}</div>` : ''}<div class="policy-weekdays">${['一','二','三','四','五','六','日'].map((day, index) => `<label><input type="checkbox" data-policy-array-check="schedule_weekdays" value="${index + 1}" ${arrayValue('schedule_weekdays').includes(String(index + 1)) ? 'checked' : ''}><span>${day}</span></label>`).join('')}</div>${editorCheck('schedule_all_day', Boolean(d.schedule_all_day), '全天')}${!d.schedule_all_day ? `<div class="policy-time-grid">${editorField('开始时间', editorInput('schedule_start', d.schedule_start, '', 'time'))}${editorField('结束时间', editorInput('schedule_end', d.schedule_end, '', 'time'))}</div>` : ''}`;
    if (mode === 'once') detail = `<div class="policy-time-grid">${editorField('日期', editorInput('schedule_date', d.schedule_date, '', 'date'))}${editorField('开始时间', editorInput('schedule_start', d.schedule_start, '', 'time'))}${editorField('结束时间', editorInput('schedule_end', d.schedule_end, '', 'time'))}</div>`;
    return `<div class="policy-subfield"><span>计划</span>${radioGroup('schedule_mode', mode, [['always','始终'],['daily','每天'],['weekly','每周'],['once','一次'],['custom','自定义']], '计划')}${detail}</div>`;
  }
  function addressTarget(prefix, isDestination = false) {
    const d = state.draft;
    const typeField = `${prefix}_type`;
    const type = d[typeField] || 'any';
    const options = isDestination ? [['any','任何'],['application','应用'],['ip','IP'],['domain','域'],['region','地区']] : [['any','任何'],['device','设备'],['network','网络'],['ip','IP'],['mac','MAC'],['identity','身份']];
    let control = '';
    if (type === 'device') control = catalogPicker(`${prefix}_devices`, 'devices', '选择设备', '暂无设备目录数据');
    if (type === 'network') control = `${catalogPicker(`${prefix}_networks`, 'networks', '选择网络', '暂无网络目录数据')}${editorCheck(`${prefix}_match_opposite`, Boolean(d[`${prefix}_match_opposite`]), '匹配相反')}${editorCheck(`${prefix}_match_mac`, Boolean(d[`${prefix}_match_mac`]), '匹配 MAC 地址')}`;
    if (type === 'identity') control = catalogPicker(`${prefix}_identities`, 'objects', '选择人员或角色', '暂无身份目录数据');
    if (type === 'ip') control = `${radioGroup(`${prefix}_match`, d[`${prefix}_match`] || 'specific', [['specific','特定'],['list','列表']], `${prefix} IP`)}${(d[`${prefix}_match`] || 'specific') === 'specific' ? bulkEntry(`${prefix}_ip`, 'IPv4/v6 地址、子网或范围') : catalogPicker(`${prefix}_ip_objects`, 'objects', '选择 IP 列表', '尚无 IP 列表对象')}${editorCheck(`${prefix}_match_opposite`, Boolean(d[`${prefix}_match_opposite`]), '匹配相反')}`;
    if (type === 'mac') control = bulkEntry(`${prefix}_mac`, '例如 ab:cd:ef:12:34:56');
    if (type === 'application') control = `${radioGroup(`${prefix}_app_mode`, d[`${prefix}_app_mode`] || 'specific', [['specific','特定'],['category','类别']], '应用匹配')}${catalogPicker(`${prefix}_applications`, 'applications', '选择应用', '暂无应用目录数据')}`;
    if (type === 'domain') control = bulkEntry(`${prefix}_domain`, 'example.com');
    if (type === 'region') control = catalogPicker(`${prefix}_regions`, 'regions', '选择地区', '尚未创建地区对象', '前往流量对象新建');
    return `${radioGroup(typeField, type, options, prefix)}${control}`;
  }
  function protocolEditor() {
    const d = state.draft;
    const protocol = d.protocol || 'all';
    return `<div class="policy-subfield"><span>协议</span>${radioGroup('protocol', protocol, [['all','全部'],['tcp_udp','TCP/UDP'],['tcp','TCP'],['udp','UDP'],['custom','自定义']], '协议')}${protocol === 'custom' ? `${editorSelect('custom_protocol', d.custom_protocol, CUSTOM_PROTOCOLS)}${editorCheck('protocol_opposite', Boolean(d.protocol_opposite), '匹配相反')}` : ''}</div>`;
  }
  function renderFirewallFields() {
    const d = state.draft;
    const autoReturnDisabled = ['wan', 'external', 'gateway'].includes(normalizeKey(d.destination_zone));
    return `${section('', editorField('名称', editorInput('name', d.name, '策略名称')))}
      ${section('源区域', `${editorSelect('source_zone', d.source_zone, zoneOptions('source_zones', d.source_zone))}${addressTarget('source')}${portEditor('source')}`)}
      ${section('操作', `${radioGroup('action', d.action, [['block','阻止'],['allow','允许'],['reject','拒绝']], '操作')}${d.action === 'allow' ? editorCheck('auto_return', Boolean(d.auto_return), '自动允许返回流量', autoReturnDisabled ? '当前区域组合不需要额外返回策略' : '自动创建与当前规则关联的返回流量策略', autoReturnDisabled) : ''}`)}
      ${section('目标区域', `${editorSelect('destination_zone', d.destination_zone, zoneOptions('destination_zones', d.destination_zone))}${addressTarget('destination', true)}${portEditor('destination')}`)}
      ${section('', `<div class="policy-subfield"><span>IP 版本</span>${radioGroup('family', d.family, [['','两者'],['ipv4','IPv4'],['ipv6','IPv6']], 'IP 版本')}</div>${protocolEditor()}<div class="policy-subfield"><span>连接状态</span>${radioGroup('connection_state', d.connection_state, [['all','全部'],['return','返回流量'],['custom','自定义']], '连接状态')}${d.connection_state === 'custom' ? `<div class="policy-state-grid">${['new','invalid','established','related'].map((value) => `<label><input type="checkbox" data-policy-array-check="connection_states" value="${value}" ${arrayValue('connection_states').includes(value) ? 'checked' : ''}><i></i><span>${{new:'新',invalid:'无效',established:'已建立',related:'相关'}[value]}</span></label>`).join('')}</div>` : ''}</div>${editorCheck('match_ipsec', d.match_ipsec, '匹配 IPsec')}${d.match_ipsec ? radioGroup('ipsec_mode', d.ipsec_mode, [['encrypted','已加密'],['unencrypted','未加密']], 'IPsec 匹配') : ''}${editorCheck('syslog', d.syslog, 'Syslog 日志')}${scheduleEditor()}${editorField('描述', `<textarea data-policy-draft="description" placeholder="可选">${escapeHtml(d.description || '')}</textarea>`)}`, 'policy-advanced-section')}`;
  }
  function renderRouteFields() {
    const d = state.draft;
    if (d.policy_type === 'static_route') return `${section('', editorField('名称', editorInput('name', d.name, '静态路由名称')))}${section('类型', `${radioGroup('route_mode', 'static', [['policy','基于策略'],['static','静态']], '路由类型')}<div class="policy-subfield"><span>设备</span>${radioGroup('route_device', 'gateway', [['gateway','Gateway'],['switch','Switch',true]], '设备')}</div>${editorField('Metric', editorInput('metric', d.metric, '0', 'number'))}${radioGroup('gateway_mode', d.gateway_mode, [['next_hop','下一跳'],['interface','接口'],['blackhole','黑洞']], '下一跳模式')}${d.gateway_mode === 'next_hop' ? editorInput('gateway', d.gateway, 'IPv4/v6 地址') : d.gateway_mode === 'interface' ? editorSelect('interface', d.interface, state.catalog.interfaces) : ''}`)}${section('目标', editorField('网络', editorInput('destination', d.destination, 'IPv4/v6 子网')))}`;
    return `${section('', editorField('名称', editorInput('name', d.name, '基于策略的路由名称')))}${section('类型', `${radioGroup('route_mode', 'policy', [['policy','基于策略'],['static','静态']], '路由类型')}${renderPbrTargetField()}${editorCheck('kill_switch', d.kill_switch, '终止开关', '所选接口不可用时阻止匹配流量')}`)}${section('源', renderPbrSourceSection())}${section('目标', `${radioGroup('destination_type', d.destination_type, [['any','任何'],['ip','IP'],['domain','域'],['region','地区']], '目标')}${d.destination_type === 'ip' ? bulkEntry('destination', 'IPv4/v6 地址、子网或范围') : d.destination_type === 'domain' ? bulkEntry('destination', 'example.com') : d.destination_type === 'region' ? catalogPicker('destination_regions','regions','选择地区','尚未创建地区对象','前往流量对象新建') : ''}`)}`;
  }
  /*
   * 出口按路由表选，不按 zone：`wan` zone 把 wan/wan6/wan2/wan3/wan4 混在一起，
   * 按 zone 选出口区分不出具体是哪条线路。
   */
  function renderPbrTargetField() {
    const d = state.draft;
    const options = pbrTargetOptions();
    if (!options.length) {
      const reason = state.routeTablesState === 'error'
        ? '路由表读取失败，暫无法选择出口。'
        : '账本里还没有任何路由表，无法指定出口线路。';
      return editorField('出口路由表', `<input type="text" value="" placeholder="无可用路由表" disabled>`, reason);
    }
    const hint = options.length === 1
      ? `当前只有 ${options[0].label} 一个出口。其他已在调度的 WAN 若不在此列表，说明它还没有对应的路由表。`
      : '出口按路由表指定，不按区域 —— 同一个 wan 区域里混着多条线路，按区域选区分不出具体走哪条。';
    return editorField('出口路由表', editorSelect('interface', d.interface, options), hint);
  }
  /*
   * 源侧两段式：先选 kind，再选 ref。kind=object 时保持原来的 IP 组/设备语义
   * （目录仍未开放，所以那一支照旧不可保存）。
   */
  function renderPbrSourceSection() {
    const d = state.draft;
    const kinds = pbrSourceKindOptions();
    const kind = normalizeKey(d.source_kind) || 'object';
    if (kinds.length <= 1) {
      /* 后端没声明多源能力时退回原样，不凭空造一个选不成的选择器。 */
      return `${radioGroup('source_type', d.source_type, [['any','任何'],['items','设备 / 网络']], '源')}${d.source_type === 'items' ? catalogPicker('source_items', 'devices', '选择设备 / 网络', '设备目录尚未提供') : ''}`;
    }
    const kindField = `<div class="policy-subfield"><span>源类型</span>${radioGroup('source_kind', kind, kinds, '源类型')}</div>`;
    let refField = '';
    if (kind === 'object') {
      refField = `${radioGroup('source_type', d.source_type, [['any','任何'],['items','设备 / 网络']], '源')}${d.source_type === 'items' ? catalogPicker('source_items', 'devices', '选择设备 / 网络', '设备目录尚未提供') : ''}`;
    } else {
      const options = pbrSourceRefOptions(kind);
      const labels = { interface: '接口', zone: '区域', network: '网络' };
      const label = labels[kind] || '来源';
      if (!options.length) {
        refField = editorField(label, `<input type="text" value="" placeholder="无可选项" disabled>`, `目录里没有可选的${label}。`);
      } else {
        const hint = kind === 'zone'
          ? '区域后面列出的是它包含的网络，按此确认选中的是目标那一段。'
          : '整段来源匹配入向接口，不需要逐台设备指定。';
        refField = editorField(label, editorSelect('source_ref', d.source_ref, options), hint);
      }
    }
    return `${kindField}${refField}${renderPbrPinWanField(kind)}`;
  }
  function renderPbrPinWanField(kind) {
    if (!pbrPinWanSupported()) return '';
    const allowed = pbrPinWanAllowed(kind);
    const consequence = pbrPinWanConsequence();
    const hint = allowed
      ? consequence
      : '仅接口 / 区域 / 网络来源可固定出口：IP 组来源没有入向接口可依据，后端会拒绝。';
    /* 后果必须和开关摆在一起：用户会把「不参与分流」读成「优先走 wan2」。 */
    return editorCheck('pin_wan', allowed && state.draft.pin_wan === true, '固定出口，不参与分流', hint, !allowed);
  }
  function renderQosFields() {
    const d=state.draft;
    const showLimit=d.qos_behavior!=='prioritize';
    return `${section('', editorField('名称', editorInput('name',d.name,'QoS 策略名称')))}${section('QoS 行为', `${radioGroup('qos_behavior',d.qos_behavior,[['limit','限制'],['prioritize','优先'],['both','优先和限制']],'QoS 行为')}${editorField('接口',editorSelect('interface',d.interface,[{value:'all',label:'所有 WAN'},...state.catalog.wans]))}${showLimit ? `${editorCheck('download_enabled',d.download_enabled,'下载限制')}${d.download_enabled ? `<div class="policy-rate-row">${editorInput('download',d.download,'10','number')}${editorSelect('download_unit',d.download_unit,[['kbps','Kbps'],['mbps','Mbps']])}</div>${radioGroup('download_burst',d.download_burst,[['off','关'],['short','短'],['long','长']],'下载突发')}`:''}${editorCheck('upload_enabled',d.upload_enabled,'上传限制')}${d.upload_enabled ? `<div class="policy-rate-row">${editorInput('upload',d.upload,'10','number')}${editorSelect('upload_unit',d.upload_unit,[['kbps','Kbps'],['mbps','Mbps']])}</div>${radioGroup('upload_burst',d.upload_burst,[['off','关'],['short','短'],['long','长']],'上传突发')}`:''}` : ''}`)}${section('源', `${radioGroup('source_type',d.source_type,[['any','任何'],['device','设备'],['network','网络']],'源')}${d.source_type==='device'?catalogPicker('source_devices','devices','选择设备','暂无设备目录数据'):d.source_type==='network'?catalogPicker('source_networks','networks','选择网络','暂无网络目录数据'):''}`)}${section('目标', `${addressTarget('destination',true)}${portEditor('destination')}`)}${section('',scheduleEditor())}`;
  }
  function renderNatFields() {
    const d=state.draft;
    return `${section('',editorField('名称',editorInput('name',d.name,'NAT 策略名称')))}${section('类型',`${radioGroup('target',d.target,[['masquerade','伪装'],['snat','源 NAT'],['dnat','目标 NAT']],'NAT 类型')}${editorField('接口 / VPN 隧道',editorSelect('interface',d.interface,[...state.catalog.wans,...state.catalog.networks]))}${d.target==='snat'?`${radioGroup('translated_ip_mode',d.translated_ip_mode,[['primary','主要地址'],['specific','特定']],'转换的 IP 地址')}${d.translated_ip_mode==='specific'?editorInput('translated_ip',d.translated_ip,'IPv4 地址、子网或范围'):''}`:d.target==='dnat'?editorField('转换的 IP 地址',editorInput('translated_ip',d.translated_ip,'IPv4 地址、子网或范围')):''}${d.target!=='masquerade'&&['tcp_udp','tcp','udp'].includes(d.protocol)?editorCheck('translate_port',d.translate_port,'转换的端口'):''}${d.translate_port?editorField('转换的端口',editorInput('translated_port',d.translated_port,'例如 443')):''}<div class="policy-subfield"><span>IP 版本</span>${radioGroup('family',d.family,[['ipv4','IPv4'],['ipv6','IPv6']],'IP 版本')}</div>${protocolEditor()}`)}${section('源',`${radioGroup('source_type',d.source_type,[['any','任何'],['network','网络'],['ip','IP']],'源')}${d.source_type==='network'?catalogPicker('source_networks','networks','选择网络','暂无网络目录数据'):d.source_type==='ip'?bulkEntry('source_ip','IPv4/v6 地址、子网或范围'):''}${portEditor('source')}`)}${section('目标',`${radioGroup('destination_type',d.destination_type,[['any','任何'],['network','网络'],['ip','IP']],'目标')}${d.destination_type==='network'?catalogPicker('destination_networks','networks','选择网络','暂无网络目录数据'):d.destination_type==='ip'?bulkEntry('destination_ip','IPv4/v6 地址、子网或范围'):''}${portEditor('destination')}`)}${section('',`${editorCheck('syslog',d.syslog,'Syslog 日志')}${editorCheck('exclude',d.exclude,'排除')}`)}`;
  }
  function renderDnsFields() {
    const d=state.draft;
    const types=[['a','主机 (A)'],['aaaa','主机 (AAAA)'],['cname','别名 (CNAME)'],['mx','邮件 (MX)'],['txt','文本 (TXT)'],['srv','服务 (SRV)'],['forward','转发域']];
    let fields='';
    if(['a','aaaa'].includes(d.record_type)) fields=`${editorField('域名',editorInput('domain',d.domain,'host.example.com'))}${editorField('IP 地址',editorInput('ip',d.ip,d.record_type==='aaaa'?'IPv6 地址':'IPv4 地址'))}`;
    if(d.record_type==='cname') fields=`${editorField('别名域',editorInput('domain',d.domain,'alias.example.com'))}${editorField('目标域',editorInput('target',d.target,'host.example.com'))}`;
    if(d.record_type==='mx') fields=`${editorField('域名',editorInput('domain',d.domain,'example.com'))}${editorField('邮件服务器',editorInput('mail_server',d.mail_server,'server.example.com'))}${editorField('优先级',editorInput('priority',d.priority,'0','number'))}`;
    if(d.record_type==='txt') fields=`${editorField('域名',editorInput('domain',d.domain,'host.example.com'))}${editorField('文本',`<textarea data-policy-draft="text" placeholder="输入文本记录">${escapeHtml(d.text||'')}</textarea>`)}`;
    if(d.record_type==='srv') fields=`${editorField('域名',editorInput('domain',d.domain,'example.com'))}${editorField('服务器',editorInput('server',d.server,'server.example.com'))}${editorField('服务',editorInput('service',d.service,'例如 _ldap'))}${editorField('协议',editorInput('dns_protocol',d.dns_protocol,'例如 _tcp'))}${editorField('端口',editorInput('port',d.port,'例如 389','number'))}${editorField('优先级',editorInput('priority',d.priority,'0','number'))}${editorField('权重',editorInput('weight',d.weight,'0','number'))}`;
    if(d.record_type==='forward') fields=`<p class="policy-field-description">将特定域的所有查询转发到不同的 DNS 服务器。</p>${editorField('域名',editorInput('domain',d.domain,'example.com'))}${editorField('DNS 服务器',editorInput('dns_server',d.dns_server,'IPv4 或 IPv6 地址'))}`;
    const ttl=['a','aaaa','cname'].includes(d.record_type)?`${editorField('TTL',radioGroup('ttl_mode',d.ttl_mode,[['auto','自动'],['manual','手动']],'TTL'))}${d.ttl_mode==='manual'?editorField('TTL（秒）',editorInput('ttl',d.ttl,'300','number')):''}`:'';
    return `${section('',editorField('类型',editorSelect('record_type',d.record_type,types)))}${section('',`${fields}${ttl}`)}`;
  }
  function renderPortForwardFields() {
    const d=state.draft;
    const wans=ipv4WanOptions().length?ipv4WanOptions():[{value:'wan',label:'WAN1'}];
    const [wanIpText,wanIpResolved]=wanAddressText(d.source_zone);
    /* 只读展示：地址由所选 WAN 接口决定，用户手填会与运行态脱节。 */
    const wanIpField=editorField('WAN IP 地址',`<input type="text" value="${escapeHtml(wanIpText)}" disabled>`,wanIpResolved?'跟随所选 WAN 接口自动变化，多线路时为该线路的公网出口地址':'');
    return `${section('',editorField('名称',editorInput('name',d.name,'端口转发名称')))}${section('',`<div class="policy-subfield"><span>WAN 接口</span>${radioGroup('source_zone',d.source_zone,[...wans.map((item)=>[item.value,item.label]),['all','所有 WAN']],'WAN 接口')}</div>${wanIpField}${editorField('WAN 端口',editorInput('external_port',d.external_port,'例如 1-10,11,12'))}<div class="policy-subfield"><span>从</span>${radioGroup('source_mode',d.source_mode,[['any','任意'],['restricted','受限']],'来源')}</div>${d.source_mode==='restricted'?`${radioGroup('source_match',d.source_match||'specific',[['specific','特定'],['list','列表']],'来源匹配')}${(d.source_match||'specific')==='specific'?bulkEntry('source_ip','IPv4 地址、子网或范围'):catalogPicker('source_ip_objects','objects','选择 IP 列表','尚无 IP 列表对象')}`:''}${editorField('转发 IP 地址',editorInput('internal_ip',d.internal_ip,'IPv4 地址'))}${catalogPicker('internal_devices','devices','选择设备','暂无设备目录数据')}${editorField('转发端口',editorInput('internal_port',d.internal_port,'例如 1-10,11,12'))}<div class="policy-subfield"><span>协议</span>${radioGroup('protocol',d.protocol,[['tcp_udp','TCP/UDP'],['tcp','TCP'],['udp','UDP']],'协议')}</div>`)}${section('',editorCheck('syslog',d.syslog,'Syslog 日志'))}`;
  }
  function unsupportedReasons() {
    const d=state.draft, reasons=[];
    /* ACL 只在后端确实没声明 MAC 写入能力时才不可保存。以前这里无条件 push
       一条"本页不重复提供表单"，等于给了入口又把保存按钮永久锁死。 */
    if(d.policy_type==='acl'&&!aclMacWritable()) reasons.push('后端未声明 MAC ACL 写入能力');
    if(d.policy_type==='firewall') {
      if(normalizeKey(d.destination_zone)==='gateway') reasons.push('Gateway 目标需要路由器本机策略链的稳定后端语义');
      if(!['any','ip'].includes(d.source_type)||!['any','ip'].includes(d.destination_type)) reasons.push('设备、网络、MAC、身份、应用、域和地区对象事务尚未实现');
      if(d.source_match==='list'||d.destination_match==='list'||d.source_port_mode==='list'||d.destination_port_mode==='list') reasons.push('对象列表引用尚未实现');
      if(d.source_match_opposite||d.destination_match_opposite||d.source_port_opposite||d.destination_port_opposite||d.source_match_mac) reasons.push('反向匹配与 MAC 匹配尚未进入写入合同');
      if(d.connection_state!=='all'||d.match_ipsec||d.syslog||d.schedule_mode!=='always'||d.description) reasons.push('连接状态、IPsec、Syslog、计划和描述字段尚未进入后端事务');
      if(d.auto_return) reasons.push('自动返回策略的关联创建与回滚事务尚未实现');
    }
    if(d.policy_type==='pbr') {
      const kind=normalizeKey(d.source_kind)||'object';
      /* 只有 object 源仍卡在对象目录上；interface/zone/network 走的是另一条
         已就绪的路（能力位 pbr_source_kinds_supported），不该被一起拦住。 */
      if(kind==='object'&&d.source_type!=='any') reasons.push('PBR 设备/网络对象目录与原子写入尚未实现');
      if(d.destination_type==='region') reasons.push('PBR 地区对象写入尚未实现');
      if(!pbrTargetOptions().length) reasons.push('账本里没有可引用的路由表，出口无合法取值');
    }
    if(d.policy_type==='qos') {
      if(d.qos_behavior!=='limit') reasons.push('当前后端只有 SQM 限速，没有 UniFi DPI 优先级队列语义');
      if(d.source_type!=='any'||d.destination_type!=='any'||d.destination_port_mode!=='any') reasons.push('QoS 源、目标和端口对象匹配尚未实现');
      if(d.download_burst!=='off'||d.upload_burst!=='off'||d.schedule_mode!=='always') reasons.push('QoS 突发与计划尚未进入后端合同');
    }
    if(d.policy_type==='nat') {
      if(d.target==='dnat') reasons.push('DNAT 请使用端口转发；config nat 执行器尚未承载 UniFi 目标 NAT 合同');
      if(d.target==='snat'&&d.translated_ip_mode==='primary') reasons.push('后端尚未提供所选接口主要地址的稳定写入解析');
      if(!['any','ip'].includes(d.source_type)||!['any','ip'].includes(d.destination_type)) reasons.push('NAT 网络对象引用尚未实现');
      if(d.source_port_mode==='list'||d.destination_port_mode==='list'||d.syslog||d.exclude) reasons.push('NAT 对象端口、Syslog 或排除语义尚未实现');
    }
    if(d.policy_type==='dns'&&!['a','aaaa','cname'].includes(d.record_type)) reasons.push('后端 dnsmasq 执行器尚未支持 MX、TXT、SRV 和转发域');
    if(d.policy_type==='dns'&&d.ttl_mode==='manual') reasons.push('DNS TTL 尚未进入写入合同');
    if(d.policy_type==='port_forwarding'&&(d.source_match==='list'||d.source_zone==='all'||d.syslog||arrayValue('internal_devices').length)) reasons.push('端口转发的对象列表、设备引用、所有 WAN 或 Syslog 语义尚未实现');
    return [...new Set(reasons)];
  }
  function renderPolicyFields() {
    const type=state.draft.policy_type;
    if(type==='firewall') return renderFirewallFields();
    if(type==='pbr'||type==='static_route') return renderRouteFields();
    if(type==='qos') return renderQosFields();
    if(type==='nat') return renderNatFields();
    if(type==='dns') return renderDnsFields();
    if(type==='port_forwarding') return renderPortForwardFields();
    if(type==='acl') return renderAclFields();
    return section('', '<div class="policy-notice">该策略类型尚无编辑器。</div>');
  }
  /*
   * ACL 面板：MAC 子类型在本页直接可填可存。
   *
   * 之所以不再只放一个跳转按钮：既然类型选择器里提供了 ACL 入口，这一页就必须
   * 能完成操作，否则用户读到的是 bug。后端 webd_policy_acl_apply_response()
   * 走的正是本页已在用的 policy-table 端点，不需要新契约。
   *
   * 控件范围严格按能力位，不多给也不少给：
   *   动作      acl_mac_supported_actions=['deny']，acl_mac_allow_supported=false
   *             （独立 nft base chain 的 accept 无法越过后续 firewall 链，
   *             这条技术限制属实，原因串照后端原话显示）
   *   时段      acl_schedule_supported=true，单窗口 + 星期，设备本地时间
   *   到期      acl_expires_supported=true，绝对 unix 秒，0=永不
   */
  function renderAclFields() {
    const d = state.draft;
    const macWritable = aclMacWritable();
    const actions = asArray(state.capabilities.acl_mac_supported_actions).map((item) => firstText(item)).filter(Boolean);
    const allowReason = firstText(state.capabilities.acl_mac_allow_reason);
    const pending = aclPendingTypes();
    if (!macWritable) {
      const pendingOnly = pending.length ? section('', renderAclPendingBlock(pending)) : '';
      return `${section('MAC 访问控制', '<div class="policy-notice">后端未声明 MAC ACL 写入能力（acl_write_supported_types 不含 mac）。</div>')}${pendingOnly}`;
    }
    const actionText = actions.length ? actions.map((item) => actionLabel(item)).join(' / ') : '阻止';
    /* 跳转按钮保留，但它现在只是"去那一页看同一条规则"，不再是写入的唯一出路。 */
    const identity = `${editorField('名称', editorInput('name', d.name, '例如 禁止访客机上网'))}${editorField('MAC 地址', editorInput('mac', d.mac, '例如 ab:cd:ef:12:34:56'), '一个 MAC 只能有一条规则；与「终端联网控制」页共用同一份规则表')}${editorField('终端备注', editorInput('terminal_name', d.terminal_name, '选填，便于在列表里识别这台设备'))}<p class="policy-field-description">规则落库在 ${escapeHtml(firstText(state.capabilities.acl_runtime_source, 'config.db:network_control_rule'))}，保存后在「终端联网控制」页可以看到同一条。<button type="button" class="policy-inline-link" data-acl-goto-mac>前往该页查看</button></p>`;
    /* 动作只有 deny 一种，做成只读陈述而不是单选：给一个只有一项的单选组
       会让用户以为还有别的选项被藏了。 */
    const actionBlock = `${editorField('动作', `<input type="text" value="${escapeHtml(actionText)}" disabled>`, '命中的 MAC 直接丢弃')}${allowReason ? `<p class="policy-field-description">放行（白名单）不可用：${escapeHtml(allowReason)}</p>` : ''}`;
    return `${section('', identity)}${section('动作', actionBlock)}${section('生效时段', renderAclScheduleFields())}${section('到期时间', renderAclExpiresFields())}${pending.length ? section('', renderAclPendingBlock(pending)) : ''}`;
  }
  function renderAclPendingBlock(pending) {
    return `<div class="policy-contract-gap"><strong>后端尚未开放的 ACL 子类型</strong>${pending.map((item) => {
      const reason = aclPendingReasonText(item);
      const alternative = aclPendingAlternativeText(item);
      const tail = [reason, alternative].filter(Boolean).join('；');
      return `<span>${escapeHtml(ACL_PENDING_LABELS[item] || item)}${tail ? `：${escapeHtml(tail)}` : ''}</span>`;
    }).join('')}</div>`;
  }
  /*
   * 时段：后端 webd_policy_acl_schedule_ok() 只接受 "always" 或恰好一个窗口的
   * JSON 数组，weekdays 是 0-6 且 0=周日。本页通用 scheduleEditor() 用的是
   * 1-7，语义不同，不能复用，否则周日会被写成 7 而被后端拒绝。
   */
  const ACL_WEEKDAYS = [[1, '一'], [2, '二'], [3, '三'], [4, '四'], [5, '五'], [6, '六'], [0, '日']];
  function renderAclScheduleFields() {
    const d = state.draft;
    if (!aclScheduleSupported()) {
      const mode = firstText(state.capabilities.acl_schedule_mode, 'always');
      return `<div class="policy-notice">后端 acl_schedule_supported=false，规则按 ${escapeHtml(mode)} 生效。</div>`;
    }
    const windowed = d.acl_schedule_mode === 'window';
    const basis = normalizeKey(firstText(state.capabilities.acl_schedule_time_basis)) === 'device_local_time'
      ? '时间按路由器本地时间判定，不是浏览器时区'
      : '';
    const weekdayBlock = aclScheduleWeekdaysSupported()
      ? `<div class="policy-weekdays">${ACL_WEEKDAYS.map(([value, label]) => `<label><input type="checkbox" data-policy-array-check="acl_schedule_weekdays" value="${value}" ${arrayValue('acl_schedule_weekdays').includes(String(value)) ? 'checked' : ''}><span>${label}</span></label>`).join('')}</div><p class="policy-field-description">不选星期表示每天都在该时间段生效。</p>`
      : '';
    const detail = windowed
      ? `<div class="policy-time-grid">${editorField('开始时间', editorInput('acl_schedule_start', d.acl_schedule_start, '', 'time'))}${editorField('结束时间', editorInput('acl_schedule_end', d.acl_schedule_end, '', 'time'))}</div>${weekdayBlock}${aclScheduleMaxWindows() === 1 ? '<p class="policy-field-description">每条规则只能有一个时间段：nftables 每条规则只匹配一个时间表达式，多个时间段需要建多条规则。</p>' : ''}${basis ? `<p class="policy-field-description">${escapeHtml(basis)}</p>` : ''}`
      : '';
    return `<div class="policy-subfield"><span>生效时段</span>${radioGroup('acl_schedule_mode', d.acl_schedule_mode || 'always', [['always', '始终生效'], ['window', '指定时间段']], '生效时段')}${detail}</div>`;
  }
  /*
   * 到期：后端存绝对 unix 秒，0=永不；已经过去的时间会被拒绝而不是静默接受。
   * 到期后规则保留行、只是不再下发（acl_expires_retains_rule=true），
   * 所以这里说明的是"停止生效"而不是"自动删除"。
   */
  function renderAclExpiresFields() {
    const d = state.draft;
    if (!aclExpiresSupported())
      return '<div class="policy-notice">后端 acl_expires_supported=false，规则不会自动失效。</div>';
    const dated = d.acl_expires_mode === 'at';
    const retains = state.capabilities.acl_expires_retains_rule === true
      ? '到期后规则会保留在列表里并停止生效，可以随时改期重新启用。'
      : '';
    return `<div class="policy-subfield"><span>到期时间</span>${radioGroup('acl_expires_mode', d.acl_expires_mode || 'never', [['never', '永不到期'], ['at', '指定时间到期']], '到期时间')}${dated ? `${editorField('到期时刻', editorInput('acl_expires_at', d.acl_expires_at, '', 'datetime-local'), '必须晚于当前时间；按路由器本地时间判定')}${retains ? `<p class="policy-field-description">${escapeHtml(retains)}</p>` : ''}` : ''}</div>`;
  }
  function renderCreatePanel() {
    if (!state.createOpen) return '';
    const editing = Boolean(state.selectedRow);
    const type = state.draft.policy_type || 'firewall';
    const reasons=unsupportedReasons();
    const canWrite = !state.selectedRow?.predefined && capabilityFor(type, editing ? 'update' : 'create');
    const canSave = canWrite && reasons.length === 0;
    return `<aside class="policy-side-panel policy-create-panel dwrt-kit-sheet policy-stable-glass is-open" data-create-panel>
      <div class="policy-side-head dwrt-kit-sheet-header"><div><strong>${editing ? escapeHtml(state.selectedRow.name) : '创建策略'}</strong></div><button class="dwrt-kit-sheet-close" type="button" data-close-create aria-label="关闭">×</button></div>
      <div class="policy-side-body dwrt-kit-sheet-body">
        ${editing ? '' : `<div class="policy-type-picker" role="radiogroup" aria-label="策略类型">${CREATE_TYPES.map((item) => `<label class="${editorType(type)===item.value?'is-active':''}${typeCanCreate(item.value)?'':' is-disabled'}"><input type="radio" data-policy-type="${escapeHtml(item.value)}" name="policy-create-type" ${editorType(type)===item.value?'checked':''} ${typeCanCreate(item.value)?'':'disabled'}><i></i><span>${escapeHtml(item.label)}</span></label>`).join('')}</div>`}
        <div class="policy-editor">${renderPolicyFields()}</div>
        ${reasons.length ? `<div class="policy-contract-gap"><strong>当前配置不能保存</strong>${reasons.map((reason)=>`<span>${escapeHtml(reason)}</span>`).join('')}</div>` : ''}
        ${state.catalogError ? `<div class="policy-notice">${escapeHtml(state.catalogError)}，部分候选项需手动填写。</div>` : ''}
        ${state.notice ? `<div class="policy-notice ${/失败|错误|不支持|请填写|必须/.test(state.notice) ? 'is-error' : ''}">${escapeHtml(state.notice)}</div>` : ''}
      </div>
      <footer class="dwrt-kit-sheet-footer"><button type="button" class="policy-secondary" data-close-create>取消</button><button type="button" class="policy-primary" data-policy-save ${canSave && !state.saving ? '' : 'disabled'}>${state.saving ? '正在保存' : canSave ? (editing?'保存':'添加策略') : reasons.length ? '等待后端能力' : '此类型不可写'}</button></footer>
    </aside>`;
  }
  function renderDetailsPanel() {
    if (!state.detailsOpen || !state.selectedRow) return '';
    const row = state.selectedRow;
    const pairs = [
      ['名称', row.name], ['策略类型', row.type], ['操作', row.action], ['协议', row.protocol], ['源区域', row.source_zone], ['源', cellText(row.source)], ['目标区域', row.destination_zone], ['目标', cellText(row.destination)], ['目标端口', row.destination_port], ['接口', row.interface], ['状态', row.enabled ? '启用' : '停用'], ['默认策略', row.predefined ? '是' : '否']
    ];
    const canUpdate = !row.predefined && capabilityFor(row.policy_type, 'update');
    const canDelete = !row.predefined && capabilityFor(row.policy_type, 'delete');
    const canToggle = !row.predefined && capabilityFor(row.policy_type, 'enable_disable');
    return `<aside class="policy-side-panel dwrt-kit-sheet dwrt-glass-card policy-stable-glass is-open" data-detail-panel>
      <div class="policy-side-head dwrt-kit-sheet-header"><div><span>Policy</span><strong>${escapeHtml(row.name)}</strong></div><button class="dwrt-kit-sheet-close" type="button" data-close-detail>×</button></div>
      <div class="policy-side-body dwrt-kit-sheet-body"><dl class="policy-detail-list">${pairs.map(([k, v]) => `<div><dt>${escapeHtml(k)}</dt><dd>${escapeHtml(v || '--')}</dd></div>`).join('')}</dl>${row.predefined ? '<div class="policy-notice">系统默认策略为只读。</div>' : ''}${state.notice ? `<div class="policy-notice ${/失败|错误/.test(state.notice) ? 'is-error' : ''}">${escapeHtml(state.notice)}</div>` : ''}</div>
      <footer class="dwrt-kit-sheet-footer policy-detail-footer"><button type="button" class="policy-secondary danger" data-policy-delete ${canDelete && !state.saving ? '' : 'disabled'}>${state.confirmDelete ? '再次点击删除' : '删除'}</button><div><button type="button" class="policy-secondary" data-policy-toggle ${canToggle && !state.saving ? '' : 'disabled'}>${row.enabled ? '停用' : '启用'}</button><button type="button" class="policy-primary" data-policy-edit ${canUpdate && !state.saving ? '' : 'disabled'}>编辑</button></div></footer>
    </aside>`;
  }

  function reloadFlags(type) {
    if (['firewall', 'port_forwarding', 'nat'].includes(type)) return { reload_firewall: true };
    if (type === 'dns') return { reload_dnsmasq: true };
    if (type === 'qos') return { reload_sqm: false };
    if (type === 'static_route') return { reload_network: false };
    if (type === 'pbr') return { reload_route: true };
    return {};
  }
  /* MAC 归一化成后端 webd_normalize_mac_text() 接受的形状：十二位十六进制，
     冒号分隔、小写。用户粘 AB-CD-EF-12-34-56 或不带分隔符都能过。 */
  function aclMacNormalized(value) {
    const hex = String(value || '').replace(/[^0-9a-fA-F]/g, '').toLowerCase();
    if (hex.length !== 12) return '';
    return hex.match(/.{2}/g).join(':');
  }
  /* schedule 以字符串提交：后端用 app_nc_json_str() 取值并判 schedule[0]==='['，
     且 config.db 的 schedule 列本身就是 TEXT。 */
  function aclScheduleValue() {
    const d = state.draft;
    if (!aclScheduleSupported() || d.acl_schedule_mode !== 'window') return 'always';
    const weekdays = aclScheduleWeekdaysSupported()
      ? [...new Set(arrayValue('acl_schedule_weekdays').map((item) => Number(item)))].filter((item) => Number.isInteger(item) && item >= 0 && item <= 6).sort((a, b) => a - b)
      : [];
    const entry = { start_time: String(d.acl_schedule_start || ''), end_time: String(d.acl_schedule_end || '') };
    if (weekdays.length) entry.weekdays = weekdays;
    return JSON.stringify([entry]);
  }
  /* expires 是绝对 unix 秒，0=永不。datetime-local 没有时区信息，按设备本地
     时间理解，与后端 acl_schedule_time_basis=device_local_time 一致。 */
  function aclExpiresValue() {
    const d = state.draft;
    if (!aclExpiresSupported() || d.acl_expires_mode !== 'at') return 0;
    const text = String(d.acl_expires_at || '').trim();
    if (!text) return 0;
    const stamp = Date.parse(text);
    if (!Number.isFinite(stamp)) return 0;
    return Math.floor(stamp / 1000);
  }
  function payloadFromDraft() {
    const d = state.draft;
    const common = { policy_type: d.policy_type, enabled: Boolean(d.enabled), apply: true, ...reloadFlags(d.policy_type) };
    /* ACL：字段名照 webd_policy_acl_copy_body_fields() 的白名单，不发它会
       忽略的字段。id 由后端生成（policy-acl-mac-<ts>-<rand>），前端不编。 */
    if (d.policy_type === 'acl') return {
      ...common,
      acl_type: 'mac',
      name: String(d.name || '').trim(),
      mac: aclMacNormalized(d.mac),
      action: 'deny',
      mode: 'deny',
      terminal_name: String(d.terminal_name || '').trim(),
      priority: Number(d.priority) || 1000,
      schedule: aclScheduleValue(),
      expires: aclExpiresValue()
    };
    if (d.policy_type === 'firewall') return { ...common, name: d.name.trim(), action: d.action, protocol: d.protocol === 'custom' ? d.custom_protocol : d.protocol, source_zone: d.source_zone, destination_zone: d.destination_zone, source_ip: d.source_type === 'ip' ? String(d.source_ip || '').trim() : '', destination_ip: d.destination_type === 'ip' ? String(d.destination_ip || '').trim() : '', source_port: d.source_port_mode === 'specific' ? String(d.source_port || d.source_port_service || '').trim() : '', destination_port: d.destination_port_mode === 'specific' ? String(d.destination_port || d.destination_port_service || '').trim() : '', family: d.family };
    if (d.policy_type === 'port_forwarding') return { ...common, name: d.name.trim(), protocol: d.protocol, source_zone: d.source_zone, destination_zone: d.destination_zone, src_dport: d.external_port.trim(), dest_ip: d.internal_ip.trim(), dest_port: d.internal_port.trim(), src_ip: d.source_mode === 'restricted' ? String(d.source_ip || '').trim() : '', family: d.family };
    if (d.policy_type === 'dns') return { ...common, record_type: d.record_type === 'cname' ? 'cname' : 'domain', name: d.domain.trim(), domain: d.domain.trim(), cname: d.domain.trim(), target: String(d.target || '').trim(), ip: String(d.ip || '').trim() };
    if (d.policy_type === 'nat') return { ...common, name: d.name.trim(), target: d.target, protocol: d.protocol === 'custom' ? d.custom_protocol : d.protocol, source_zone: d.source_type === 'network' ? firstText(arrayValue('source_networks')[0]) : 'lan', destination_zone: d.interface || 'wan', source_ip: d.source_type === 'ip' ? String(d.source_ip || '').trim() : '', destination_ip: d.destination_type === 'ip' ? String(d.destination_ip || '').trim() : '', source_port: d.source_port_mode === 'specific' ? String(d.source_port || d.source_port_service || '').trim() : '', destination_port: d.destination_port_mode === 'specific' ? String(d.destination_port || d.destination_port_service || '').trim() : '', snat_ip: d.target === 'snat' ? String(d.translated_ip || '').trim() : '', snat_port: d.translate_port ? String(d.translated_port || '').trim() : '', family: d.family };
    if (d.policy_type === 'static_route') return { ...common, name: d.name.trim(), family: d.family, target: d.destination.trim(), destination: d.destination.trim(), gateway: d.gateway_mode === 'next_hop' ? d.gateway.trim() : '', interface: d.gateway_mode === 'interface' ? d.interface.trim() : '', table: d.table.trim() || 'main', metric: Number(d.metric) || 0, mtu: Number(d.mtu) || 1500, route_kind: d.gateway_mode === 'blackhole' ? 'blackhole' : (d.route_kind || 'unicast'), source: d.source.trim() };
    if (d.policy_type === 'qos') { const rate=(value,unit)=>String(Math.max(0,Number(value)||0)*(unit==='mbps'?1000:1)); return { ...common, name: d.name.trim(), interface: d.interface.trim(), download: d.download_enabled ? rate(d.download,d.download_unit) : '0', upload: d.upload_enabled ? rate(d.upload,d.upload_unit) : '0', qdisc: d.qdisc, script: d.script, linklayer: d.linklayer, overhead: String(d.overhead ?? '').trim() }; }
    if (d.policy_type === 'pbr') {
      const kind = normalizeKey(d.source_kind) || 'object';
      const ref = String(d.source_ref || '').trim();
      const table = String(d.interface || '').trim();
      const base = { ...common, name: d.name.trim(), dest_object: d.destination_type === 'any' ? 'any' : String(d.destination || '').trim(), protocol: d.protocol, ports: String(d.ports || 'any').trim() || 'any', action: d.action, target: table, route_table: table, priority: Number(d.priority) || 1000, schedule: 'always', comment: d.comment.trim() };
      /* object 源保持老形状：后端见到 source_ref 而 kind=object 会直接报错，
         所以非 object 分支才带 source_ref，object 分支一个字段都不多发。 */
      if (kind === 'object')
        return { ...base, source_kind: 'object', source_object: d.source_type === 'any' ? 'any' : firstText(arrayValue('source_items')[0]) || 'any' };
      return { ...base, source_kind: kind, source_ref: ref, source_object: 'any', pin_wan: pbrPinWanAllowed(kind) && d.pin_wan === true };
    }
    return common;
  }
  function validateDraft() {
    const d = state.draft;
    const unsupported = unsupportedReasons();
    if (unsupported.length) return unsupported[0] + '。';
    /* ACL 的校验对齐后端 webd_policy_acl_build_rule()：在这里说清楚，
       比让用户吃一个 400 再猜哪个字段不对要好。 */
    if (d.policy_type === 'acl') {
      const name = String(d.name || '').trim();
      if (!name) return '请填写策略名称。';
      if (name.length > 64) return '策略名称不能超过 64 个字符。';
      if (!String(d.mac || '').trim()) return '请填写要阻止的 MAC 地址。';
      if (!aclMacNormalized(d.mac)) return 'MAC 地址格式不正确，应为 12 位十六进制，例如 ab:cd:ef:12:34:56。';
      if (aclScheduleSupported() && d.acl_schedule_mode === 'window') {
        const start = String(d.acl_schedule_start || '').trim();
        const end = String(d.acl_schedule_end || '').trim();
        if (!start || !end) return '请填写生效时段的开始与结束时间。';
        if (start === end) return '开始时间与结束时间不能相同，否则时间段永不命中。';
      }
      if (aclExpiresSupported() && d.acl_expires_mode === 'at') {
        const expires = aclExpiresValue();
        if (!expires) return '请填写到期时刻，或选择永不到期。';
        if (expires <= Math.floor(Date.now() / 1000)) return '到期时刻必须晚于当前时间，否则规则永远不会生效。';
      }
      return '';
    }
    if (['firewall', 'port_forwarding', 'nat', 'pbr'].includes(d.policy_type) && !d.name.trim()) return '请填写策略名称。';
    if (d.policy_type === 'port_forwarding' && !d.external_port.trim()) return '请填写外部端口。';
    if (d.policy_type === 'port_forwarding' && !d.internal_ip.trim()) return '请填写内部 IP。';
    if (d.policy_type === 'dns' && !d.domain.trim()) return '请填写域名。';
    if (d.policy_type === 'dns' && d.record_type === 'cname' && !d.target.trim()) return '请填写 CNAME 目标域名。';
    if (d.policy_type === 'dns' && d.record_type !== 'cname' && !String(d.ip || '').trim()) return '请填写 IP 地址。';
    if (d.policy_type === 'nat' && d.target === 'snat' && d.translated_ip_mode === 'specific' && !String(d.translated_ip || '').trim()) return '源 NAT 必须填写转换后的 IP。';
    if (d.policy_type === 'static_route' && !d.destination.trim()) return '请填写目标网络。';
    if (d.policy_type === 'static_route' && !d.gateway.trim() && !d.interface.trim()) return '下一跳和接口至少填写一项。';
    if (d.policy_type === 'qos' && !d.name.trim()) return '请填写 QoS 策略名称。';
    if (d.policy_type === 'qos' && !d.interface.trim()) return '请选择 QoS 接口。';
    if (d.policy_type === 'qos' && !d.download_enabled && !d.upload_enabled) return '下载限制和上传限制至少启用一项。';
    if (d.policy_type === 'pbr' && d.action !== 'main' && !String(d.interface || '').trim()) return '请选择策略路由的出口路由表。';
    if (d.policy_type === 'pbr' && (normalizeKey(d.source_kind) || 'object') !== 'object' && !String(d.source_ref || '').trim()) return '请选择来源的接口 / 区域 / 网络。';
    return '';
  }
  async function savePolicy() {
    const error = validateDraft();
    if (error) { state.notice = error; render(); return; }
    const editing = Boolean(state.selectedRow);
    if (!capabilityFor(state.draft.policy_type, editing ? 'update' : 'create')) { state.notice = '后端未开放此策略类型的写入。'; render(); return; }
    state.saving = true;
    state.notice = '';
    render();
    try {
      const payload = payloadFromDraft();
      if (editing) await requestJson(`${ENDPOINT}/${encodeURIComponent(state.selectedRow.id)}?apply=true`, { method: 'PATCH', body: JSON.stringify(payload) });
      else await requestJson(`${ENDPOINT}?apply=true`, { method: 'POST', body: JSON.stringify(payload) });
      state.saving = false;
      state.createOpen = false;
      state.selectedRow = null;
      render();
      await load();
    } catch (errorValue) {
      state.saving = false;
      state.notice = `保存失败：${firstText(errorValue?.message, '未知错误')}`;
      render();
    }
  }
  async function deletePolicy() {
    const row = state.selectedRow;
    if (!row || row.predefined || !capabilityFor(row.policy_type, 'delete')) return;
    if (!state.confirmDelete) { state.confirmDelete = true; render(); return; }
    state.saving = true;
    state.notice = '';
    render();
    try {
      await requestJson(`${ENDPOINT}/${encodeURIComponent(row.id)}?apply=true`, { method: 'DELETE', body: JSON.stringify({ policy_type: row.policy_type, apply: true, ...reloadFlags(row.policy_type) }) });
      state.saving = false;
      state.detailsOpen = false;
      state.selectedRow = null;
      render();
      await load();
    } catch (errorValue) {
      state.saving = false;
      state.confirmDelete = false;
      state.notice = `删除失败：${firstText(errorValue?.message, '未知错误')}`;
      render();
    }
  }
  async function togglePolicy() {
    const row = state.selectedRow;
    if (!row || row.predefined || !capabilityFor(row.policy_type, 'enable_disable')) return;
    state.saving = true;
    state.notice = '';
    render();
    const operation = row.enabled ? 'disable' : 'enable';
    try {
      await requestJson(`${ENDPOINT}/${encodeURIComponent(row.id)}/${operation}?apply=true`, { method: 'POST', body: JSON.stringify({ policy_type: row.policy_type, apply: true, ...reloadFlags(row.policy_type) }) });
      state.saving = false;
      state.detailsOpen = false;
      state.selectedRow = null;
      render();
      await load();
    } catch (errorValue) {
      state.saving = false;
      state.notice = `${row.enabled ? '停用' : '启用'}失败：${firstText(errorValue?.message, '未知错误')}`;
      render();
    }
  }
  function renderCell(row, column) {
    switch (column.key) {
      case 'expand': return row.children?.length ? `<button type="button" class="policy-expand" data-expand-row="${escapeHtml(row.id)}" aria-label="展开"><span>${state.expandedRows.has(row.id) ? '−' : '+'}</span></button>` : '';
      case 'name': return `<button type="button" class="policy-name-button" data-open-row="${escapeHtml(row.id)}" title="${escapeHtml(row.name)}">${escapeHtml(row.name)}</button>`;
      case 'type': return escapeHtml(row.type);
      case 'action': return `<span class="policy-action policy-action-${escapeHtml(row.action_key)}">${escapeHtml(row.action)}</span>`;
      case 'protocol': return escapeHtml(row.protocol || '--');
      case 'source_zone': return compactValue(row.source_zone);
      case 'source': return compactValue(row.source);
      case 'destination_zone': return compactValue(row.destination_zone);
      case 'destination': return compactValue(row.destination);
      case 'destination_port': return escapeHtml(row.destination_port || '--');
      case 'interface': return compactValue(row.interface);
      default: return '';
    }
  }
  /*
   * cols 是必传的。给它一个 `= activeColumns()` 的默认值反而危险：漏传时会静默地
   * 重新求值一次列集合，而展开列的可见性取决于数据，正是这样才出现过表头 10 列 /
   * 数据行 11 格。缺参数应当当场炸掉，而不是渲染出一张错位的表。
   */
  function renderRow(row, nested, cols) {
    if (!Array.isArray(cols)) throw new Error('renderRow 必须显式接收列集合 cols');
    const classes = ['policy-row', nested ? 'is-child' : '', !row.enabled ? 'is-disabled' : ''].filter(Boolean).join(' ');
    const html = `<tr class="${classes}" data-row-id="${escapeHtml(row.id)}">${cols.map((column) => `<td class="policy-col-${escapeHtml(column.key)}">${renderCell(row, column)}</td>`).join('')}</tr>`;
    /* 子行必须沿用同一份列集合，否则表头 / colgroup 与数据行的格子数会错开。 */
    const children = !nested && state.expandedRows.has(row.id) ? (row.children || []).map((child) => renderRow(child, true, cols)).join('') : '';
    return html + children;
  }
  function renderTable() {
    /* Column widths live in a <colgroup> because the table is table-layout: fixed.
       Fixed layout takes its widths from the first row and honours `width` only --
       `min-width` on a th/td is ignored outright. The widths used to be written as
       inline min-width on the <th>, so every one of them was dropped and the 11
       columns simply split the table evenly: measured 113px each on 30.1, which
       gave the empty expand column 113px and pushed 名称 about 300px in from the
       card edge. (.policy-col-expand's width: 46px did not save it either -- that
       rule targets the td, and under fixed layout only the first row counts.) */
    const rows = visibleRows();
    const cols = activeColumns();
    return `<section class="policy-table-card dwrt-kit-table-wrap dwrt-kit-ikuai-table-wrap policy-stable-glass">
      <div class="dwrt-kit-table-toolbar policy-table-toolbar">
        <span class="dwrt-kit-table-count">${tableCountText(rows)}</span>
        ${tableActionsMarkup()}
      </div>
      <div class="dwrt-kit-table-scroll policy-table-scroll" data-table-scroll>
        <table class="dwrt-kit-table dwrt-kit-ikuai-table policy-table" style="--policy-table-min-width:${tableMinWidth(cols)}px">
          ${columnGroupMarkup(cols)}
          <thead><tr>${cols.map((column) => `<th>${escapeHtml(column.label)}</th>`).join('')}</tr></thead>
          <tbody>${tableBodyMarkup(rows, cols)}</tbody>
        </table>
      </div>
      <div class="policy-table-foot"><button type="button" data-reorder disabled>重新排序</button></div>
    </section>`;
  }
  /*
   * 徽章文本与 tbody 必须出自同一次 visibleRows() 求值，所以都收进 helper，
   * 并且只通过 writeTableContents() 一起落到 DOM 上。
   *
   * 病灶（Acceptance 2026-08-05）：徽章原先只写在 renderTable() 的模板里，
   * 而快路径 patchPolicyTable() 为了保住滚动位置**只换 tbody**。首屏是
   * 「先渲染空表 → 数据到达后走快路径填 tbody」，于是表体已是 42 行、徽章还留着
   * 第一次渲染的 rows.length === 0，屏幕上「策略表 0 条」与 42 行策略同时出现。
   * 列数变化时快路径会 return render() 整表重绘，那种情况下徽章才跟着对 ——
   * 所以它看起来像「改了筛选就自己好了」的偶发问题，其实是必然的。
   */
  function tableCountText(rows) {
    return `${rows.length} 条`;
  }
  function tableBodyMarkup(rows, cols) {
    if (state.loading) return '<tr><td colspan="20" class="dwrt-kit-table-empty policy-empty-cell">正在读取策略表…</td></tr>';
    if (!rows.length) return '<tr><td colspan="20" class="dwrt-kit-table-empty policy-empty-cell">没有匹配的策略</td></tr>';
    return rows.map((row) => renderRow(row, false, cols)).join('');
  }
  /*
   * 表格内容的最小 patch 单元 = tbody + 计数徽章。以后再加别的快路径请调用这里，
   * 不要单独写 tbody.innerHTML，否则又会漏掉一个展示位。
   */
  function writeTableContents(tbody, rows, cols) {
    tbody.innerHTML = tableBodyMarkup(rows, cols);
    const countEl = root?.querySelector('.policy-table-card .dwrt-kit-table-count');
    if (countEl) countEl.textContent = tableCountText(rows);
  }
  function bindPolicyTableRows() {
    root.querySelectorAll('[data-expand-row]').forEach((button) => button.addEventListener('click', (event) => { event.stopPropagation(); toggleSet(state.expandedRows, button.dataset.expandRow); render(); }));
    root.querySelectorAll('[data-open-row]').forEach((button) => button.addEventListener('click', () => {
      const id = button.dataset.openRow;
      state.selectedRow = state.rows.find((row) => row.id === id) || null;
      state.detailsOpen = Boolean(state.selectedRow);
      state.createOpen = false;
      state.notice = '';
      state.confirmDelete = false;
      render();
    }));
  }
  function patchPolicyTable() {
    const tbody = root.querySelector('.policy-table tbody');
    if (!tbody) return render();
    const scroll = root.querySelector('[data-table-scroll]');
    const scrollTop = scroll?.scrollTop || 0;
    const scrollLeft = scroll?.scrollLeft || 0;
    const rows = visibleRows();
    /*
     * 只换 tbody 的前提是列集合没变。展开列的可见性取决于数据里有没有子行，
     * 筛选一改就可能变；此时表头与 colgroup 还是旧的，数据行却按新列集合渲染，
     * 整行会右移一列。列数不一致就整表重绘。
     */
    const cols = activeColumns();
    const renderedCols = root.querySelectorAll('.policy-table colgroup col').length;
    if (renderedCols && renderedCols !== cols.length) return render();
    /* tbody 与计数徽章一起写，二者同源于上面那一次 visibleRows()。 */
    writeTableContents(tbody, rows, cols);
    bindPolicyTableRows();
    if (scroll) {
      scroll.scrollTop = scrollTop;
      scroll.scrollLeft = scrollLeft;
    }
  }
  function patchPolicyStatus() {
    const shell = root.querySelector('.policy-table-shell');
    const table = root.querySelector('.policy-table-card');
    if (!shell || !table) return false;
    const status = renderStatus();
    let line = shell.querySelector(':scope > .policy-status-line');
    if (!status) {
      line?.remove();
      return true;
    }
    if (!line) {
      line = document.createElement('div');
      line.className = 'policy-status-line';
      shell.insertBefore(line, table);
    }
    line.classList.toggle('is-warning', Boolean(state.error));
    line.textContent = status;
    return true;
  }
  function patchPolicyToolbar() {
    const createButton = root.querySelector('[data-open-create]');
    if (!createButton) return;
    const enabled = !state.loading && state.capabilities.create === true;
    createButton.disabled = !enabled;
    const label = createButton.querySelector('span');
    if (label) label.textContent = state.loading ? '正在读取能力' : '创建新策略';
  }
  function patchPolicyView() {
    if (!root?.querySelector('.policy-table-shell')) return render();
    patchPolicyToolbar();
    patchPolicyStatus();
    patchPolicyTable();
    patchOverlays();
  }

  /*
   * 抽屉层（筛选抽屉、列面板、创建/详情侧栏及其遮罩）不再是整页模板的一部分。
   *
   * 病灶：这些面板原先直接拼进 `render()` 的模板字符串，而 `render()` 是
   * `root.innerHTML = ...` 整块重写。抽屉里任何一次交互 —— 打一个字、勾一个
   * 复选框、点一次筛选项 —— 都会走到 `render()`，把正在使用的抽屉连根拔掉再造
   * 一个新的。用户看到的就是「弹出之后立马闪退」「点一下整个抽屉重新加载」，
   * 焦点、光标位置、以及正在进行的文本选择全部丢失（复制会被打断就是这个原因）。
   *
   * 现在抽屉渲染进独立宿主 `[data-policy-overlay-host]`，主体重绘不碰它；
   * 抽屉自身的状态变化走 `patchOverlays()` 只替换宿主内容。
   *
   * 注意 kit 的 `mountAll()` 会把 `.dwrt-kit-sheet` 搬到 body 直属的
   * `#dwrtKitSheetPortal`（祖先链上的 transform/filter 会让 position:fixed
   * 重新锚定，所以抽屉必须离开路由宿主）。因此清理旧抽屉时要连传送门里的一起
   * 收走，只清宿主会留下孤儿节点，表现为抽屉叠了好几层。
   */
  function overlayMarkup() {
    const drawerBackdrop = state.drawerOpen
      ? '<button type="button" class="policy-drawer-backdrop dwrt-kit-sheet-overlay" data-close-filter aria-label="关闭筛选"></button>'
      : '';
    const sideBackdrop = state.createOpen || state.detailsOpen
      ? '<button type="button" class="policy-drawer-backdrop dwrt-kit-sheet-overlay" data-close-side aria-label="关闭侧边面板"></button>'
      : '';
    return `${drawerBackdrop}${sideBackdrop}${renderDrawer()}${renderColumnsPanel()}${renderCreatePanel()}${renderDetailsPanel()}`;
  }

  function clearPortaledOverlays() {
    document.querySelectorAll('#dwrtKitSheetPortal [data-policy-overlay-owned]').forEach((node) => node.remove());
  }

  /* 壳层那两个 is-* 标记原本由整页重绘顺手写上，现在主体不重绘了，单独同步。 */
  function syncShellFlags() {
    const shell = root?.querySelector('.policy-table-shell');
    if (!shell) return;
    shell.classList.toggle('is-filter-open', Boolean(state.drawerOpen));
    shell.classList.toggle('is-side-open', Boolean(state.createOpen || state.detailsOpen));
  }

  /*
   * 绑定用的查询范围 = 路由宿主 + kit 传送门里属于本页的节点。
   * 只查 root 会漏掉已经被搬进 #dwrtKitSheetPortal 的抽屉（那才是抽屉真正待的
   * 地方），漏掉的后果是抽屉里所有控件失效。
   */
  function scopedAll(selector) {
    const found = [];
    if (root) found.push(...root.querySelectorAll(selector));
    document.querySelectorAll('#dwrtKitSheetPortal [data-policy-overlay-owned]').forEach((node) => {
      if (node.matches?.(selector)) found.push(node);
      found.push(...node.querySelectorAll(selector));
    });
    /*
     * 去重：抽屉层每次重绘都要重新绑定，但同一次 bindEvents() 也会扫到主体里
     * 那些没有被替换过的节点。不挡住的话监听会一层层叠加，一次点击触发多次
     * （表现为筛选跳两格、抽屉开了又立刻关）。带过标记的节点直接跳过。
     */
    let seen = boundNodes.get(selector);
    if (!seen) { seen = new WeakSet(); boundNodes.set(selector, seen); }
    return found.filter((node) => {
      if (seen.has(node)) return false;
      seen.add(node);
      return true;
    });
  }

  function renderOverlays() {
    const host = root?.querySelector('[data-policy-overlay-host]');
    if (!host) return;
    clearPortaledOverlays();
    host.innerHTML = overlayMarkup();
    host.querySelectorAll('.dwrt-kit-sheet, .policy-drawer-backdrop, .policy-popover')
      .forEach((node) => node.setAttribute('data-policy-overlay-owned', ''));
    ui.mountAll?.(host);
  }

  /*
   * 只重绘抽屉层。主体（工具栏 / 状态行 / 表格）保持原样，不动 DOM。
   *
   * 还要再进一步：抽屉**已经开着**时连它的外壳也不能换。重建外壳会让 kit 重新
   * 播放入场动画、丢掉滚动位置和焦点，勾一个复选框就闪一下 —— 这正是用户说的
   * 「点一下里面的东西整个抽屉重新加载」。所以已在场的抽屉只换正文，
   * 外壳（页头 / 页脚 / 玻璃层）原地保留。
   */
  function patchOverlays() {
    /* 换正文之前先记住焦点在不在应用搜索框上、光标在哪。见 restoreAppSearchFocus()。 */
    const focusState = captureAppSearchFocus();
    const live = liveSheets();
    /* 抽屉集合发生增减（开了新面板、关掉旧面板）必须整层重建；
       只有集合不变、纯粹是内容变化时才走「只换正文」的轻量路径。 */
    const template = document.createElement('div');
    template.innerHTML = overlayMarkup();
    const nextMarkers = [...template.querySelectorAll('.dwrt-kit-sheet')].map((n) => sheetMarker(n)).sort().join('|');
    const liveMarkers = live.map((n) => sheetMarker(n)).sort().join('|');
    if (!live.length || nextMarkers !== liveMarkers) { renderOverlays(); bindEvents(); restoreAppSearchFocus(focusState); return; }

    let replaced = 0;
    live.forEach((sheet) => {
      const marker = sheetMarker(sheet);
      if (!marker) return;
      const next = template.querySelector(`.dwrt-kit-sheet${marker}`);
      if (!next) return;
      const currentBody = sheet.querySelector('.dwrt-kit-sheet-body');
      const nextBody = next.querySelector('.dwrt-kit-sheet-body');
      if (!currentBody || !nextBody) return;
      const scrollTop = currentBody.scrollTop;
      currentBody.innerHTML = nextBody.innerHTML;
      currentBody.scrollTop = scrollTop;
      const currentFoot = sheet.querySelector('.dwrt-kit-sheet-footer');
      const nextFoot = next.querySelector('.dwrt-kit-sheet-footer');
      if (currentFoot && nextFoot) currentFoot.innerHTML = nextFoot.innerHTML;
      replaced += 1;
    });

    /* 抽屉集合本身发生了增减（开了新面板、关掉了旧面板）就只能整层重来。 */
    if (!replaced) { renderOverlays(); }
    bindEvents();
    restoreAppSearchFocus(focusState);
  }

  /*
   * 应用搜索框的焦点保全。服务端搜索每次回来都要重绘候选列表，而重绘走的是
   * currentBody.innerHTML = ... —— 输入框是个全新节点，焦点和光标都没了，
   * 表现就是"打一个字焦点就掉，第二个字打不进去"。所以换正文前记下状态，换完还回去。
   */
  function captureAppSearchFocus() {
    const active = document.activeElement;
    if (!active?.dataset?.policyPickerRemote) return null;
    return { key: active.dataset.policyPickerRemote, start: active.selectionStart, end: active.selectionEnd };
  }
  function restoreAppSearchFocus(focusState) {
    if (!focusState) return;
    const input = document.querySelector(`[data-policy-picker-remote="${focusState.key}"]`);
    if (!input || input === document.activeElement) return;
    input.focus();
    /* search 类型的 input 支持 setSelectionRange，但个别浏览器会抛，失败就只保焦点。 */
    try { input.setSelectionRange(focusState.start ?? input.value.length, focusState.end ?? input.value.length); } catch (_) {}
  }

  /* 当前真正可见的抽屉（kit 搬走之后它们住在传送门里）。 */
  function liveSheets() {
    return [...document.querySelectorAll('[data-policy-overlay-owned].dwrt-kit-sheet, [data-policy-overlay-host] .dwrt-kit-sheet')]
      .filter((node) => node.getBoundingClientRect().width > 0);
  }

  /* 用一个稳定的类名把抽屉和模板里的同一个面板对上。 */
  function sheetMarker(sheet) {
    for (const cls of ['policy-filter-drawer', 'policy-create-panel', 'policy-side-panel']) {
      if (sheet.classList.contains(cls)) return `.${cls}`;
    }
    return '';
  }

  function render() {
    if (!root) return;
    const previousSideScroll = root.querySelector('.policy-side-body')?.scrollTop || 0;
    root.hidden = false;
    root.classList.remove('route-line-status', 'route-data-page', 'route-client-details-host', 'route-insights-host', 'route-insights-home', 'route-log-center-host');
    root.classList.add('route-workspace', MODULE_CLASS);
    const status = renderStatus();
    root.innerHTML = `<section class="policy-table-shell${state.drawerOpen ? ' is-filter-open' : ''}${state.createOpen || state.detailsOpen ? ' is-side-open' : ''}">
      ${status ? `<div class="policy-status-line${state.error ? ' is-warning' : ''}">${escapeHtml(status)}</div>` : ''}
      ${renderTable()}
      <div class="policy-overlay-host" data-policy-overlay-host></div>
    </section>`;
    renderOverlays();
    bindEvents();
    ui.mountAll?.(root);
    const nextSideBody = root.querySelector('.policy-side-body');
    if (nextSideBody) nextSideBody.scrollTop = previousSideScroll;
  }
  function bindEvents() {
    /*
     * `scope()` 代替裸 `root`：kit 的 mountAll() 会把抽屉搬到 body 直属的
     * #dwrtKitSheetPortal，搬走之后抽屉不再是 root 的后代，`scopedAll`
     * 一个都选不到，抽屉里的按钮和字段就全成了死的。这里把宿主和传送门里属于
     * 本页的节点合并成一个查询范围，绑定逻辑本身不用改。
     */
    /* 开关抽屉只需要重绘抽屉层：主体没有变化，重绘主体反而会毁掉抽屉。 */
    scopedAll('[data-open-filter]').forEach((button) => button.addEventListener('click', () => { state.drawerOpen = true; syncShellFlags(); patchOverlays(); }));
    scopedAll('[data-open-columns]').forEach((button) => button.addEventListener('click', () => { state.columnsOpen = true; syncShellFlags(); patchOverlays(); }));
    scopedAll('[data-open-create]').forEach((button) => button.addEventListener('click', () => { state.createOpen = true; state.detailsOpen = false; state.selectedRow = null; state.draft = newDraft(writeTypes().has('firewall') ? 'firewall' : [...writeTypes()][0]); state.notice = ''; state.confirmDelete = false; syncShellFlags(); patchOverlays(); }));
    scopedAll('[data-close-filter]').forEach((button) => button.addEventListener('click', () => { state.drawerOpen = false; syncShellFlags(); patchOverlays(); }));
    scopedAll('[data-close-columns]').forEach((button) => button.addEventListener('click', () => { state.columnsOpen = false; syncShellFlags(); patchOverlays(); }));
    scopedAll('[data-close-create]').forEach((button) => button.addEventListener('click', () => { state.createOpen = false; state.selectedRow = null; state.notice = ''; syncShellFlags(); patchOverlays(); }));
    scopedAll('[data-close-detail]').forEach((button) => button.addEventListener('click', () => { state.detailsOpen = false; state.selectedRow = null; state.notice = ''; state.confirmDelete = false; syncShellFlags(); patchOverlays(); }));
    scopedAll('[data-close-side]').forEach((button) => button.addEventListener('click', () => { state.createOpen = false; state.detailsOpen = false; state.selectedRow = null; state.notice = ''; state.confirmDelete = false; syncShellFlags(); patchOverlays(); }));
    scopedAll('[data-policy-type]').forEach((input) => input.addEventListener('change', () => { state.draft = newDraft(input.dataset.policyType === 'route' ? 'pbr' : input.dataset.policyType); state.notice = ''; state.pickerOpen=''; patchOverlays(); }));
    scopedAll('[data-policy-radio]').forEach((input) => input.addEventListener('change', () => {
      const field=input.dataset.policyRadio;
      if(field==='route_mode') {
        const name=state.draft.name;
        state.draft=newDraft(input.value==='static'?'static_route':'pbr');
        state.draft.name=name;
      } else if(field==='source_kind') {
        /* 换 kind 就要清掉上一 kind 的 ref：zone 的 dw_lan2 拿到 interface
           下面是无效值，留着会提交出一条后端拒绝的规则。pin_wan 在 object
           上不合法，切回 object 时一起关掉。 */
        state.draft.source_kind=input.value;
        state.draft.source_ref=pbrSourceRefOptions(input.value)[0]?.value||'';
        if(!pbrPinWanAllowed(input.value)) state.draft.pin_wan=false;
      } else state.draft[field]=input.value;
      state.notice=''; state.pickerOpen=''; patchOverlays();
    }));
    scopedAll('[data-policy-check]').forEach((input) => input.addEventListener('change', () => { state.draft[input.dataset.policyCheck]=input.checked; state.notice=''; patchOverlays(); }));
    scopedAll('[data-policy-array-check]').forEach((input) => input.addEventListener('change', () => {
      const field=input.dataset.policyArrayCheck;
      const values=new Set(arrayValue(field).map(String));
      if(input.checked) values.add(String(input.value)); else values.delete(String(input.value));
      state.draft[field]=[...values]; state.notice=''; patchOverlays();
    }));
    scopedAll('[data-policy-picker]').forEach((button)=>button.addEventListener('click',()=>{
      const next=state.pickerOpen===button.dataset.policyPicker?'':button.dataset.policyPicker;
      /* 关掉选择器时取消未触发的防抖搜索：否则面板已经收起，一次请求还会在
         300ms 后打出去并重绘，用户看到的是"关了又自己动一下"。 */
      if(!next) window.clearTimeout(appSearchTimer);
      state.pickerOpen=next;
      patchOverlays();
    }));
    scopedAll('[data-policy-pick]').forEach((input)=>input.addEventListener('change',()=>{
      const field=input.dataset.policyPick, values=new Set(arrayValue(field));
      if(input.checked)values.add(input.value);else values.delete(input.value);
      state.draft[field]=[...values]; state.notice=''; patchOverlays();
    }));
    scopedAll('[data-policy-pick-all]').forEach((button)=>button.addEventListener('click',()=>{state.draft[button.dataset.policyPickAll]=(state.catalog[button.dataset.catalogKey]||[]).map((item)=>item.value);patchOverlays();}));
    /*
     * 两种搜索行为，按候选源区分：
     *  - 应用（remote）：回后端查 app_q。以前只过滤已渲染的 DOM 行，用户搜前 100 条
     *    之外的应用永远是空结果，比"数量少"更误导人。
     *  - 其他候选源：仍在本地过滤，它们几十条数据全在手上，没必要多一次请求。
     */
    scopedAll('[data-policy-picker-search]').forEach((input)=>input.addEventListener('input',()=>{
      const remoteKey=input.dataset.policyPickerRemote;
      if(remoteKey){
        appSearchQuery=input.value;
        window.clearTimeout(appSearchTimer);
        appSearchTimer=window.setTimeout(()=>{ if(mounted) loadApplications(appSearchQuery.trim(), 0); }, 300);
        return;
      }
      const query=input.value.trim().toLowerCase();
      input.closest('.policy-object-menu')?.querySelectorAll(':scope > div > label').forEach((row)=>{row.hidden=query&&!row.textContent.toLowerCase().includes(query);});
    }));
    scopedAll('[data-policy-pick-more]').forEach((button)=>button.addEventListener('click',()=>{
      if(state.appCatalog.loading||!state.appCatalog.hasMore) return;
      loadApplications(state.appCatalog.query, state.appCatalog.loaded);
    }));
    scopedAll('[data-policy-bulk]').forEach((button)=>button.addEventListener('click',()=>{const field=button.dataset.policyBulk;if(state.bulkInputs.has(field))state.bulkInputs.delete(field);else state.bulkInputs.add(field);patchOverlays();}));
    scopedAll('[data-policy-draft]').forEach((input) => input.addEventListener('input', () => {
      state.draft[input.dataset.policyDraft] = input.type === 'number' ? Number(input.value) : input.value;
      state.notice = '';
      if (input.tagName === 'SELECT' && ['record_type', 'target', 'protocol', 'ttl_mode', 'translated_ip_mode', 'download_unit', 'upload_unit'].includes(input.dataset.policyDraft)) patchOverlays();
    }));
    scopedAll('[data-policy-draft-check]').forEach((input) => input.addEventListener('change', () => { state.draft[input.dataset.policyDraftCheck] = input.checked; }));
    scopedAll('[data-policy-save]').forEach((button) => button.addEventListener('click', savePolicy));
    scopedAll('[data-acl-goto-mac]').forEach((button) => button.addEventListener('click', () => {
      state.createOpen = false;
      syncShellFlags();
      window.location.hash = ACL_MAC_ROUTE;
    }));
    /* 空态的「前往流量对象新建」：关掉抽屉再跳，否则返回时抽屉还盖在页面上。 */
    scopedAll('[data-policy-goto-objects]').forEach((button) => button.addEventListener('click', () => {
      state.createOpen = false;
      state.detailsOpen = false;
      state.pickerOpen = '';
      syncShellFlags();
      window.location.hash = FLOW_OBJECT_ROUTE;
    }));
    scopedAll('[data-policy-edit]').forEach((button) => button.addEventListener('click', () => { if (!state.selectedRow) return; state.draft = draftFromRow(state.selectedRow); state.detailsOpen = false; state.createOpen = true; state.notice = ''; state.confirmDelete = false; patchOverlays(); }));
    scopedAll('[data-policy-delete]').forEach((button) => button.addEventListener('click', deletePolicy));
    scopedAll('[data-policy-toggle]').forEach((button) => button.addEventListener('click', togglePolicy));
    scopedAll('[data-toggle-section]').forEach((button) => button.addEventListener('click', () => { toggleSet(state.collapsed, button.dataset.toggleSection); patchOverlays(); }));
    /* 筛选类操作既改抽屉里的勾选态，也改表格内容：两边都要更新，但都用增量，
       不能回到整页 render()，否则抽屉又被连根拔掉。 */
    scopedAll('[data-clear-filters]').forEach((button) => button.addEventListener('click', () => {
      state.query = '';
      state.showDefault = true;
      state.type = 'all';
      Object.values(state.selectedFilters).forEach((set) => set.clear());
      patchPolicyTable();
      patchPolicyStatus();
      patchOverlays();
    }));
    scopedAll('[data-show-default]').forEach((input) => input.addEventListener('change', () => { state.showDefault = input.checked; patchPolicyTable(); patchPolicyStatus(); patchOverlays(); }));
    scopedAll('[data-filter-key]').forEach((input) => input.addEventListener('change', () => {
      const key = input.dataset.filterKey;
      const value = normalizeKey(input.value);
      if (key === 'policy_type') state.type = value || 'all';
      else toggleSet(state.selectedFilters[key], value);
      patchPolicyTable();
      patchPolicyStatus();
      patchOverlays();
    }));
    scopedAll('[data-column-toggle]').forEach((input) => input.addEventListener('change', () => {
      if (input.checked) state.visibleColumns.add(input.value);
      else state.visibleColumns.delete(input.value);
      patchPolicyTable();
      patchOverlays();
    }));
    bindPolicyTableRows();
    scopedAll('[data-policy-search], [data-policy-search-drawer]').forEach((input) => input.addEventListener('input', () => {
      window.clearTimeout(searchTimer);
      const value = input.value;
      searchTimer = window.setTimeout(() => {
        state.query = value;
        /* 抽屉里的搜索框以前走 render()，等于边打字边把自己所在的抽屉拆掉，
           每敲一个字符都丢焦点 —— 这是「复制/输入老自己跳」最直接的来源。 */
        patchPolicyTable();
        patchPolicyStatus();
      }, 120);
    }));
  }

  render();
  load();

  return {
    unmount() {
      mounted = false;
      window.clearTimeout(searchTimer);
      window.clearTimeout(appSearchTimer);
      if (state.abort) state.abort.abort();
      if (root) root.replaceChildren();
      root?.classList.remove(MODULE_CLASS, 'route-workspace');
    }
  };
}

export default { mount };
