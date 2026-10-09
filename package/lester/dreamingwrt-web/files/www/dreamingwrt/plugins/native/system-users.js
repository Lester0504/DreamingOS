const SYSTEM_USERS_VERSION = '20260809-user-policy-gates-01';

/*
 * 「活动」Tab 的 range 候选。这是**探测候选**，不是能力声明：
 * 后端 `webd_user_activity()`（jmx_app_api.c:50245）只在响应里回显当前
 * `range` 与 `bucket_seconds`，不下发可选档位枚举，所以前端无法从任何
 * 端点读到「有哪几档」。候选逐个提交，后端答 400 `invalid_range` 的档位
 * 会被从切换器里剔除，答 200 的档位其刻度与窗口一律取响应里的
 * `bucket_seconds` / `window_start` / `window_end`，不在前端写死。
 * 后端若下线某一档，这里会跟着少一颗按钮，而不是继续画一个必然 400 的档位。
 * （已提交交接单请求后端把档位枚举下发到 capabilities，届时这份候选可删。）
 */
export const SYSTEM_USER_ACTIVITY_RANGE_CANDIDATES = ['1d', '1w', '1m', '3m'];

/*
 * 「设置」Tab 可写字段的白名单，逐项对齐后端 PATCH /api/v1/system/users/<username>
 * 的 `webd_directory_user_update()`（jmx_app_api.c:49502）。这里只列后端真的会
 * COALESCE 落库的列，参照图里 UniFi 有、本项目后端没有的字段（Employee ID、
 * First/Last Name 拆分）一律不出现——画一个存不进去的输入框就是假表单。
 */
export const SYSTEM_USER_PERMISSION_CHOICES = [
  ['read', '只读访问'],
  ['write.low', '低风险写入'],
  ['write.medium', '中风险写入'],
  ['write.high', '高风险写入'],
  ['ai.low', 'AI 低风险'],
  ['dreamingproxy.read', '代理：读取'],
  ['dreamingproxy.operate', '代理：运行'],
  ['dreamingproxy.configure', '代理：配置'],
  ['dreamingproxy.apply', '代理：下发'],
  ['dreamingproxy.secrets', '代理：凭据'],
  ['dreamingproxy.audit', '代理：审计']
];

function avatarText(value) {
  if (value === undefined || value === null) return '';
  if (typeof value === 'object' && !Array.isArray(value)) {
    return avatarText(value.url || value.path || value.src || value.avatar_url || value.avatar);
  }
  return String(value).trim();
}

export function normalizeSystemUserAvatarUrl(value, baseHref = globalThis.location?.href || 'http://localhost/') {
  let source = avatarText(value);
  if (!source) return '';
  if (/^data:image\/(?:png|jpeg|webp);base64,/i.test(source) || /^blob:/i.test(source)) return source;
  if (source.includes('\\') || /(?:^|\/)\.\.(?:\/|$)/.test(source)) return '';
  if (source.startsWith('/www/luci-static/')) source = source.slice(4);
  else if (source.startsWith('/www/dreamingwrt/static/')) source = source.slice('/www/dreamingwrt'.length);
  else if (/^(?:luci-static|static)\//i.test(source)) source = `/${source}`;
  try {
    const base = new URL(baseHref);
    const url = new URL(source, base);
    if (!/^https?:$/.test(url.protocol) || url.origin !== base.origin) return '';
    if (!/^\/(?:luci-static|static)\//.test(url.pathname)) return '';
    return `${url.pathname}${url.search}`;
  } catch (_) {
    return '';
  }
}

export function withSystemUserAvatarRevision(value, revision, baseHref = globalThis.location?.href || 'http://localhost/') {
  const normalized = normalizeSystemUserAvatarUrl(value, baseHref);
  if (!normalized || /^(?:data:image|blob:)/i.test(normalized) || !revision) return normalized;
  try {
    const url = new URL(normalized, baseHref);
    url.searchParams.set('v', String(revision));
    return `${url.pathname}${url.search}`;
  } catch (_) {
    return normalized;
  }
}

export function mergeSystemUserAvatar(users = [], current = {}) {
  const username = avatarText(current.username).toLowerCase();
  const avatarUrl = normalizeSystemUserAvatarUrl(current.avatar_url || current.avatarUrl || current.avatar);
  if (!username || !avatarUrl) return users;
  return users.map((user) => avatarText(user.username).toLowerCase() === username ? { ...user, avatarUrl } : user);
}

export function mount(context = {}) {
  const root = context.root || document.getElementById('routePreview');
  const api = context.api || {};
  const ui = context.ui || {};
  const utils = context.utils || {};
  const escapeHtml = utils.escapeHtml || ((value) => String(value ?? '').replace(/[&<>"']/g, (ch) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[ch])));
  const VERSION = SYSTEM_USERS_VERSION;
  const USERS_ENDPOINT = '/api/v1/system/users';
  const GROUPS_ENDPOINT = '/api/v1/system/user-groups';
  const ROLES_ENDPOINT = '/api/v1/system/user-roles';
  const BASIC_ENDPOINT = '/api/v1/system/basic';
  /*
   * API 密钥。路由确认存在：`strings /usr/bin/dreamingwrt-webd` 里有
   * `/api/v1/auth/api-keys` 与 `/api/v1/auth/api-keys/`，后端也有完整的
   * `api_keys` 表与增删改查 SQL。它是 medium 风险，viewer 读会拿到
   * 403 `role 'viewer' cannot perform 'medium' risk action`——**这不是路由缺失**，
   * 所以 API 管理页要把 403 说成「当前账号权限不足」，不能说成「后端未提供」
   * （design.md Capability truth 第 1、2 条）。
   */
  const API_KEYS_ENDPOINT = '/api/v1/auth/api-keys';
  const MODULE_CLASS = 'system-users-route-host';

  /*
   * 页面级一级 Tab（用户 2026-08-05：「用户页面新增三个 tab：用户、组、API 管理」）。
   * 「组」原先只是工具栏上一个「管理组」按钮弹出的抽屉，数据与能力位早就齐了
   * （`system/user-groups` 200，capabilities 里 group_read/group_create/update 均 true），
   * 这里把它提升为一级视图；抽屉入口保留，两条路径读同一份 state.groups。
   */
  const PAGE_TABS = [
    ['users', '用户'],
    ['groups', '组'],
    ['api', 'API 管理']
  ];

  const state = {
    mounted: true,
    loading: true,
    error: '',
    groupsError: '',
    source: '',
    users: [],
    groups: [],
    roles: [],
    capabilities: {},
    query: '',
    permission: 'all',
    createMenu: false,
    pageTab: 'users',
    /*
     * API 密钥的运行时状态。可用性由**实际请求的结果**决定，不写死：
     * 403 是权限不足（路由存在），404 才是路由缺失，两者必须分开说。
     */
    apiKeys: {
      probe: 'idle',
      error: '',
      errorKind: '',
      items: [],
      capabilities: {},
      /* 创建表单草稿。抽屉关闭时清空，明文不落 state 之外的任何地方。 */
      draft: null,
      notice: '',
      /* 创建成功后后端唯一一次返回的明文，复制走之后就再也读不到。 */
      created: null
    },
    drawer: '',
    selected: null,
    detailTab: 'overview',
    settingsDraft: null,
    settingsError: '',
    /*
     * 活动 Tab 的运行时状态。可用性**只**由 `probe` 决定（'idle' | 'loading'
     * | 'ready' | 分类后的失败种类），页面里没有任何写死的可用/不可用字面量。
     * `ranges` 初始为候选集，后端拒绝某档时把它剔除。
     */
    activity: {
      username: '',
      probe: 'idle',
      error: '',
      range: '',
      type: 'all',
      ranges: [...SYSTEM_USER_ACTIVITY_RANGE_CANDIDATES],
      data: null,
      seq: 0
    },
    draft: {},
    importRows: [],
    importName: '',
    importErrors: [],
    groupDraftOpen: false,
    groupDraft: {},
    saving: false,
    notice: '',
    currentUsername: '',
    avatarRevision: Date.now(),
    seq: 0,
    pollTimer: 0
  };

  function firstText(...values) {
    for (const value of values) {
      if (value === undefined || value === null) continue;
      if (typeof value === 'object' && !Array.isArray(value)) {
        const nested = firstText(value.name, value.label, value.value, value.id);
        if (nested) return nested;
        continue;
      }
      const text = String(value).trim();
      if (text) return text;
    }
    return '';
  }

  function firstNumber(...values) {
    for (const value of values) {
      const number = Number(value);
      if (Number.isFinite(number)) return number;
    }
    return 0;
  }

  function asArray(value, keys = []) {
    if (Array.isArray(value)) return value;
    if (!value || typeof value !== 'object') return [];
    for (const key of [...keys, 'items', 'rows', 'data']) {
      if (Array.isArray(value[key])) return value[key];
    }
    return [];
  }

  function unwrap(value) {
    let current = value?.data ?? value ?? {};
    for (let index = 0; index < 3; index += 1) {
      if (!current || typeof current !== 'object' || Array.isArray(current) || !current.data || typeof current.data !== 'object') break;
      current = current.data;
    }
    return current || {};
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
    return { ...(token ? { Authorization: `Bearer ${token}` } : {}), ...(typeof api.authHeaders === 'function' ? api.authHeaders() : {}), ...extra };
  }

  async function requestJson(url, options = {}) {
    const response = await sessionFetch(`${url}${url.includes('?') ? '&' : '?'}v=${encodeURIComponent(VERSION)}`, {
      credentials: 'same-origin',
      cache: 'no-store',
      ...options,
      headers: authHeaders({ Accept: 'application/json', ...(options.body ? { 'Content-Type': 'application/json' } : {}), ...(options.headers || {}) })
    });
    const text = await response.text();
    let json = {};
    if (text) {
      try { json = JSON.parse(text); } catch (_) { throw new Error('后端返回了无效 JSON'); }
    }
    if (!response.ok || json?.ok === false) {
      const error = new Error(firstText(json?.error?.message, json?.error?.code, json?.message, json?.code, `${response.status}`));
      error.status = response.status;
      error.payload = json;
      throw error;
    }
    return unwrap(json);
  }

  function normalizePermissions(value) {
    if (Array.isArray(value)) return value.map((item) => firstText(item)).filter(Boolean);
    if (value && typeof value === 'object') return Object.entries(value).filter(([, enabled]) => Boolean(enabled)).map(([key]) => key);
    return firstText(value).split(/[;,]/).map((item) => item.trim()).filter(Boolean);
  }

  function normalizeUser(value = {}, index = 0) {
    const username = firstText(value.username, value.name, value.display_name, value.id, `user-${index + 1}`);
    const permissions = normalizePermissions(value.permissions || value.permissions_json || value.permission);
    const groupValues = asArray(value.groups || value.user_groups).map((group) => firstText(group)).filter(Boolean);
    return {
      id: firstText(value.id, value.uuid, username),
      username,
      displayName: firstText(value.display_name, value.full_name, value.name, username),
      email: firstText(value.email),
      status: firstText(value.status, value.state, value.enabled === false ? 'disabled' : 'active').toLowerCase(),
      role: firstText(value.role, value.role_name, 'admin'),
      permissions,
      groups: groupValues,
      assignments: asArray(value.assignments || value.sites || value.resources).map((item) => firstText(item)).filter(Boolean),
      credentials: asArray(value.credentials || value.auth_methods).map((item) => firstText(item)).filter(Boolean),
      twofa: Boolean(value.twofa_enabled || value.two_factor || value.otp_enabled),
      avatarUrl: normalizeSystemUserAvatarUrl(value.avatar_url || value.avatarUrl || value.avatar || value.photo_url || value.profile_image),
      createdAt: firstNumber(value.created_at, value.added_at),
      updatedAt: firstNumber(value.updated_at),
      lastActivity: firstNumber(value.last_activity, value.last_login_at, value.last_seen),
      /*
       * 单用户级 API-Key 禁令与周期性改密。两者后端都还没有存储列，
       * 所以这里只做「有就读、没有就是 undefined」，绝不在前端伪造默认值：
       * 读出 undefined 与读出 false 是两件事，前者表示后端没这个字段，
       * 后者表示后端明确说没禁。渲染层据此分别措辞。
       */
      apiKeyCreateDenied: firstBool(value.api_key_create_denied, value.apiKeyCreateDenied,
                                    value.api_key_create_allowed === false ? true : undefined),
      passwordRotateDays: firstOptionalNumber(value.password_rotate_days, value.passwordRotateDays,
                                              value.password_max_age_days),
      passwordChangedAt: firstOptionalNumber(value.password_changed_at, value.passwordChangedAt),
      passwordMustChange: firstBool(value.password_must_change, value.passwordMustChange),
      raw: value
    };
  }

  /*
   * 三态布尔：`undefined` 表示后端根本没给这个键，`true` / `false` 才是后端的判定。
   * 用 `Boolean(x)` 会把「没这个字段」压成 false，界面就会把未实现的能力
   * 说成「已确认未开启」——design.md Capability truth 第 4 条明确禁止。
   */
  function firstBool(...values) {
    for (const value of values) {
      if (value === true || value === false) return value;
      if (value === 1) return true;
      if (value === 0) return false;
    }
    return undefined;
  }

  /* 同上，数值版：读不到返回 undefined，而不是 0（0 在周期改密里意味着「不强制」）。 */
  function firstOptionalNumber(...values) {
    for (const value of values) {
      if (value === undefined || value === null || value === '') continue;
      const number = Number(value);
      if (Number.isFinite(number)) return number;
    }
    return undefined;
  }

  function normalizeGroup(value = {}, index = 0) {
    const users = asArray(value.users || value.members).map((item) => firstText(item.username, item.name, item.id, item)).filter(Boolean);
    return {
      id: firstText(value.id, value.uuid, value.name, `group-${index + 1}`),
      name: firstText(value.name, value.label, `用户组 ${index + 1}`),
      users,
      userCount: Math.max(users.length, firstNumber(value.user_count, value.count)),
      description: firstText(value.description, value.remark, value.note),
      /*
       * 组级权限档。后端目前没有这两列（`web_user_groups` 只有
       * id / name / description / created_at / updated_at），读不到就是 undefined，
       * 不在前端补一个看起来像真值的默认档。
       */
      permissionTier: firstText(value.permission_tier, value.permissionTier, value.tier) || undefined,
      permissions: value.permissions === undefined && value.permissions_json === undefined
        ? undefined
        : normalizePermissions(value.permissions || value.permissions_json),
      raw: value
    };
  }

  function normalizeCapabilities(data = {}) {
    const caps = data.capabilities && typeof data.capabilities === 'object' ? data.capabilities : {};
    const writable = data.writable === true || caps.write === true || caps.writable === true;
    return {
      create: writable || caps.create === true,
      update: writable || caps.update === true,
      delete: writable || caps.delete === true,
      import: writable || caps.import === true,
      export: caps.export === true,
      groups: caps.groups === true || caps.group_read === true,
      groupCreate: writable || caps.group_create === true,
      groupUpdate: writable || caps.group_update === true,
      /*
       * 三项新能力位，各自独立读，缺键即 undefined（= 后端还没这个能力源）。
       * 不让它们继承 `writable`：用户目录整体可写，并不代表后端已经能存
       * 「禁止建 Key」「组权限档」「周期改密」这三样东西——把它们挂在 writable
       * 上会让表单在没有存储列的情况下亮起来，提交后静默丢弃。
       */
      apiKeyDenyPerUser: caps.api_key_deny_per_user === true ? true
        : (caps.api_key_deny_per_user === false ? false : undefined),
      groupPermissionTier: caps.group_permission_tier === true ? true
        : (caps.group_permission_tier === false ? false : undefined),
      passwordRotation: caps.password_rotation === true ? true
        : (caps.password_rotation === false ? false : undefined),
      /* 后端下发的档位枚举；空数组与缺键都表示「没有可选档」，不自造一张表。 */
      groupPermissionTiers: Array.isArray(caps.group_permission_tiers)
        ? caps.group_permission_tiers.filter((tier) => tier && typeof tier === 'object')
        : [],
      /*
       * 周期性改密的可选周期。后端给了就以它为准，缺键时为空数组，
       * 渲染层退回本地候选并由后端校验（同 activity range 的做法）。
       */
      passwordRotateChoices: Array.isArray(caps.password_rotate_choices)
        ? caps.password_rotate_choices.filter((item) => item !== undefined && item !== null)
        : [],
      /*
       * API-Key 专属位。`revoke` 与 `create` 分开读，因为后端可能只放开其中
       * 一个；`tiers` 是后端真的接受的档位枚举，前端据此出选项而不是自己
       * 维护一张会漂移的表（design.md「参数只能提供后端接受的字段」）。
       * `createReason` 只在能力位为 false 时由后端给出，用来说明为什么灰掉，
       * 避免前端拿"后端未开放"这种与事实相反的兜底措辞。
       */
      revoke: writable || caps.revoke === true,
      audit: caps.audit === true,
      read: caps.read === true,
      tiers: Array.isArray(caps.tiers) ? caps.tiers.filter((tier) => typeof tier === 'string' && tier) : [],
      writeMinRole: typeof caps.write_min_role === 'string' ? caps.write_min_role : '',
      createReason: typeof caps.create_reason === 'string' ? caps.create_reason : ''
    };
  }

  // 404/405/501 means the route is genuinely absent; 401/403 are session or permission
  // problems and 5xx is a backend fault. Reporting them all as "not implemented" hid a
  // delivered capability.
  function directoryUnavailabilityMessage(error) {
    const status = Number(error?.status) || 0;
    if (status === 404 || status === 405 || status === 501) return `用户目录接口未实现（HTTP ${status}），当前只显示真实登录用户。`;
    if (status === 401) return '会话已失效，请重新登录后查看完整用户目录。';
    if (status === 403) return '当前账号没有查看用户目录的权限，仅显示自身账号。';
    if (status >= 500) return `用户目录读取失败：后端错误 HTTP ${status}。`;
    if (status) return `用户目录读取失败：HTTP ${status}。`;
    return `用户目录读取失败：${firstText(error?.message, '网络不可用')}。`;
  }

  function groupsUnavailabilityMessage(error) {
    const status = Number(error?.status) || 0;
    if (status === 404 || status === 405 || status === 501) return `用户组接口未实现（HTTP ${status}）`;
    if (status === 401) return '会话已失效，请重新登录';
    if (status === 403) return '当前账号没有查看用户组的权限';
    if (status >= 500) return `用户组读取失败：后端错误 HTTP ${status}`;
    if (status) return `用户组读取失败：HTTP ${status}`;
    return `用户组读取失败：${firstText(error?.message, '网络不可用')}`;
  }

  function fallbackUser(data = {}) {
    const admin = data.admin && typeof data.admin === 'object' ? data.admin : {};
    const twofa = data.twofa && typeof data.twofa === 'object' ? data.twofa : {};
    return normalizeUser({
      username: firstText(admin.username, twofa.username, localStorage.getItem('dreamingwrt.web.username'), 'root'),
      display_name: firstText(admin.display_name, admin.username, twofa.username, 'root'),
      role: firstText(admin.role, localStorage.getItem('dreamingwrt.web.role'), 'admin'),
      status: 'active',
      twofa_enabled: Boolean(twofa.twofa_enabled || admin.two_factor),
      avatar_url: firstText(admin.avatar_url, admin.avatar),
      last_login_at: admin.last_login_at,
      created_at: admin.created_at,
      permissions: admin.permissions || []
    });
  }

  /*
   * 首屏 401 的自愈入口：请会话闸门强制刷一次令牌。
   *
   * 走闸门自己的 refresh() 而不是在这里手写 POST /api/v1/session/refresh：闸门的
   * `refreshPromise` 是单例，并发页面的刷新会合并成一次，成功后 token 也已经写回
   * localStorage，后续 requestJson() 自然带上新令牌。`retryRequired: true` 是必需的
   * ——闸门在判定 `required` 之后会拒绝普通刷新请求，而首屏这一发 401 往往正好把
   * `required` 置了位。闸门缺失（单测/无壳环境）时返回 false，调用方落回分档文案。
   */
  async function refreshSession() {
    const gate = globalThis.DWRT_SESSION;
    if (!gate || typeof gate.refresh !== 'function') return false;
    try {
      return Boolean(await gate.refresh({ force: true, retryRequired: true }));
    } catch (_) {
      return false;
    }
  }

  /*
   * 目录读取失败时的降级视图：只显示当前登录用户，并给出分档原因。
   * 从 load() 里提出来，是因为「首次失败」和「刷新后重试仍失败」两条路径要落到
   * 完全一样的状态，重复写两遍必然写歪一处。
   */
  function applyDirectoryFallback(basic, error) {
    state.users = [fallbackUser(basic)];
    state.groups = [];
    state.roles = [];
    state.capabilities = normalizeCapabilities({});
    state.source = 'system/basic · 当前登录用户';
    state.error = directoryUnavailabilityMessage(error);
  }

  async function load() {
    const seq = ++state.seq;
    state.loading = true;
    state.error = '';
    render();
    try {
      /*
       * `/api/v1/system/users` is the authority for the user directory. The capability
       * batch on `system/basic` is attached from the auth state and can be absent for
       * session reasons, so it must not gate this request.
       *
       * 这里必须是独立的 try/catch。此前 `basic` 是外层 try 的第一条语句，它一失败就
       * 直接跳到外层 catch，`USERS_ENDPOINT` 压根不会被调用 —— 正好就是上面这条注释
       * 说不该发生的「被 basic 卡住」。首屏令牌还没就绪时 basic 拿 401，整张表被清空
       * 成 `读取用户失败：401` 死在那里（Acceptance 2026-08-05 实机复现）。
       * basic 失败只该影响 `state.currentUsername`，它本身就有 localStorage 兜底。
       */
      let basic = {};
      try {
        basic = await requestJson(BASIC_ENDPOINT);
      } catch (_) {
        basic = {};
      }
      if (!state.mounted || seq !== state.seq) return;
      const currentAdmin = basic.admin && typeof basic.admin === 'object' ? basic.admin : {};
      state.currentUsername = firstText(currentAdmin.username, basic.twofa?.username, localStorage.getItem('dreamingwrt.web.username'));
      let usersData;
      try {
        usersData = await requestJson(USERS_ENDPOINT);
      } catch (error) {
        if (!state.mounted || seq !== state.seq) return;
        /*
         * 首屏自愈：外壳可能还没把令牌准备好，`load()` 就已经打出去了，于是拿到 401。
         * 令牌其实有效，只是时序早了一步，所以刷一次会话再重试一次，而不是把表清空
         * 停在错误态等用户手动刷浏览器。刷新与重试都失败才落到分档文案。
         */
        if (Number(error?.status) === 401 && await refreshSession()) {
          if (!state.mounted || seq !== state.seq) return;
          try {
            usersData = await requestJson(USERS_ENDPOINT);
          } catch (retryError) {
            if (!state.mounted || seq !== state.seq) return;
            applyDirectoryFallback(basic, retryError);
            return;
          }
        } else {
          applyDirectoryFallback(basic, error);
          return;
        }
      }
      if (!state.mounted || seq !== state.seq) return;
      state.users = mergeSystemUserAvatar(
        asArray(usersData.users || usersData, ['users']).map(normalizeUser),
        { username: state.currentUsername, avatar_url: firstText(currentAdmin.avatar_url, currentAdmin.avatar) }
      );
      state.capabilities = normalizeCapabilities(usersData);
      state.source = firstText(usersData.source, 'config.db:web_users');
      const [groupsResult, rolesResult] = await Promise.allSettled([requestJson(GROUPS_ENDPOINT), requestJson(ROLES_ENDPOINT)]);
      if (!state.mounted || seq !== state.seq) return;
      if (groupsResult.status === 'fulfilled') {
        state.groups = asArray(groupsResult.value.groups || groupsResult.value, ['groups']).map(normalizeGroup);
        state.capabilities.groups = true;
        state.groupsError = '';
      } else {
        state.groups = [];
        state.capabilities.groups = false;
        state.groupsError = groupsUnavailabilityMessage(groupsResult.reason);
      }
      if (rolesResult.status === 'fulfilled') state.roles = asArray(rolesResult.value.roles || rolesResult.value, ['roles']);
    } catch (error) {
      if (!state.mounted || seq !== state.seq) return;
      /*
       * 兜底文案也走分档。此前这里是裸的 `读取用户失败：${message}`，401 时就显示
       * 「读取用户失败：401」，比内层 directoryUnavailabilityMessage() 的分档措辞差得多。
       */
      state.users = [];
      state.error = directoryUnavailabilityMessage(error);
    } finally {
      if (!state.mounted || seq !== state.seq) return;
      state.loading = false;
      if (document.activeElement?.matches('[data-system-user-search]')) patchLoadedUsers();
      else render();
    }
  }

  /*
   * 读 API 密钥列表。按需触发：只有切到「API 管理」Tab 才请求，
   * 页面初次加载不为一个可能没人看的 Tab 付一次往返。
   *
   * 可用性由**响应本身**决定，页面里没有写死的可用/不可用字面量：
   * 403 是权限不足（路由确实存在，`strings` 里有 `/api/v1/auth/api-keys`），
   * 404 才是没实现。两者必须分开措辞，否则就会把「你这个账号看不了」
   * 说成「固件没这功能」（design.md Capability truth 第 1、2 条）。
   */
  async function loadApiKeys() {
    if (!state.mounted) return;
    if (state.apiKeys.probe === 'loading') return;
    state.apiKeys.probe = 'loading';
    state.apiKeys.error = '';
    patchPageTabPanel();
    const seq = state.seq;
    try {
      const data = await requestJson(API_KEYS_ENDPOINT);
      if (!state.mounted || seq !== state.seq) return;
      state.apiKeys.items = asArray(data.keys || data.api_keys || data, ['keys', 'api_keys']).map(normalizeApiKey);
      state.apiKeys.capabilities = normalizeCapabilities(data);
      state.apiKeys.probe = 'ready';
      state.apiKeys.error = '';
      state.apiKeys.errorKind = '';
    } catch (error) {
      if (!state.mounted || seq !== state.seq) return;
      /*
       * subject 前面留一个空格，再把整句 trim 掉首尾。
       *
       * 分档文案有两种形状：`当前账号无权读取${subject}`（subject 在后）与
       * `${subject}接口未在当前固件实现`（subject 在前）。subject 以拉丁字母
       * 开头时前者会粘成「读取API 密钥」，补一个前导空格即可；而后者又会因此
       * 多出一个行首空格，所以取用时统一 trim。改这里而不改
       * classifyApiFailure()，是因为它的另一个调用方 subject 是纯中文，
       * 不需要这个空格。
       */
      const classified = classifyApiFailure(error, ' API 密钥');
      classified.message = String(classified.message || '').trim();
      state.apiKeys.items = [];
      state.apiKeys.probe = classified.kind === 'unimplemented' ? 'unimplemented' : classified.kind;
      state.apiKeys.errorKind = classified.kind;
      state.apiKeys.error = classified.message;
    } finally {
      if (!state.mounted || seq !== state.seq) return;
      patchPageTabPanel();
    }
  }

  /*
   * API 密钥行。字段名对齐后端 `api_keys` 表
   * （key_id / name / tier / scope_json / allow_ips / expires_at / revoked_at /
   * created_at / last_used_at / last_used_ip / use_count / created_by）。
   * 兼容 camelCase 是因为其他端点两种风格都出现过。
   */
  function normalizeApiKey(value) {
    const raw = value && typeof value === 'object' ? value : {};
    const revokedAt = Math.round(firstNumber(raw.revoked_at, raw.revokedAt, 0));
    const expiresAt = Math.round(firstNumber(raw.expires_at, raw.expiresAt, 0));
    const now = Math.floor(Date.now() / 1000);
    return {
      id: firstText(raw.key_id, raw.keyId, raw.id),
      name: firstText(raw.name, '未命名密钥'),
      tier: firstText(raw.tier, 'read_only'),
      allowIps: firstText(raw.allow_ips, raw.allowIps),
      createdBy: firstText(raw.created_by, raw.createdBy),
      createdAt: Math.round(firstNumber(raw.created_at, raw.createdAt, 0)),
      expiresAt,
      revokedAt,
      lastUsedAt: Math.round(firstNumber(raw.last_used_at, raw.lastUsedAt, 0)),
      lastUsedIp: firstText(raw.last_used_ip, raw.lastUsedIp),
      useCount: Math.round(firstNumber(raw.use_count, raw.useCount, 0)),
      /* 撤销优先于过期：一把被撤销的密钥即便还没到期也已经不能用了。 */
      status: revokedAt > 0 ? 'revoked' : (expiresAt > 0 && expiresAt <= now ? 'expired' : 'active')
    };
  }

  function icon(name) {
    const paths = {
      search: '<circle cx="11" cy="11" r="7"></circle><path d="m16.5 16.5 4 4"></path>',
      plus: '<path d="M12 5v14M5 12h14"></path>',
      upload: '<path d="M12 16V4m0 0L7.5 8.5M12 4l4.5 4.5"></path><path d="M5 14v5h14v-5"></path>',
      users: '<circle cx="9" cy="8" r="3"></circle><path d="M3.5 19a5.5 5.5 0 0 1 11 0M15 6.5a2.5 2.5 0 0 1 0 5M16 14a4.5 4.5 0 0 1 4.5 4.5"></path>',
      refresh: '<path d="M20 11a8 8 0 1 0 1 4"></path><path d="M20 4v7h-7"></path>',
      chevron: '<path d="m8 10 4 4 4-4"></path>',
      close: '<path d="m6 6 12 12M18 6 6 18"></path>',
      profile: '<circle cx="12" cy="8" r="3.4"></circle><path d="M5.5 19.5a6.5 6.5 0 0 1 13 0"></path>',
      activity: '<path d="M3 12h4l2.5-6 4 12 2.5-6h5"></path>',
      settings: '<circle cx="12" cy="12" r="3"></circle><path d="M12 3.5v2.2M12 18.3v2.2M4.9 7.8l1.9 1.1M17.2 15.1l1.9 1.1M4.9 16.2l1.9-1.1M17.2 8.9l1.9-1.1"></path>'
    };
    return `<svg viewBox="0 0 24 24" aria-hidden="true">${paths[name] || paths.users}</svg>`;
  }

  function formatTime(value) {
    const raw = Number(value) || 0;
    if (!raw) return '--';
    const timestamp = raw < 100000000000 ? raw * 1000 : raw;
    return new Intl.DateTimeFormat('zh-CN', { year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit' }).format(timestamp);
  }

  function statusLabel(user) {
    return /disabled|inactive|locked|off/.test(user.status) ? '已停用' : '活跃';
  }

  /*
   * 失败分类，按 design.md「Capability truth and failure classification」第 3 条：
   * 404/405/501 是接口未实现，401 会话失效，403 权限不足，5xx 后端错误，无状态码是网络不可用。
   * `error.code` 优先于状态码——同一后端在不同构建下会用不同状态码表达同一件事。
   * 口径与 ai-assistant.js:525 的 classifyApiFailure() 一致，措辞按本页主题调整。
   */
  function classifyApiFailure(error, subject = '数据') {
    const code = firstText(error?.payload?.error?.code, error?.payload?.code);
    if (code === 'method_not_registered') return { kind: 'unimplemented', message: `${subject}对应的能力尚未接入当前固件` };
    if (code === 'source_unavailable') return { kind: 'unavailable', message: `${subject}服务暂时不可用，请稍后重试` };
    /*
     * viewer 读他人活动是后端刻意的隔离（`activity_forbidden`，
     * jmx_app_api.c:50227），不是缺陷，所以单列一支并按「只能看自己」措辞。
     */
    if (code === 'activity_forbidden') return { kind: 'forbidden', message: '当前账号只能查看自己的活动记录' };
    if (code === 'invalid_range') return { kind: 'invalid_range', message: '后端不接受这个时间范围' };
    const status = Math.round(firstNumber(error?.status, 0));
    if (!status) return { kind: 'network', message: `无法连接路由器，${subject}读取失败` };
    if (status === 401) return { kind: 'unauthorized', message: '登录状态已失效，请重新登录' };
    if (status === 403) return { kind: 'forbidden', message: `当前账号无权读取${subject}` };
    if (status === 404 || status === 405 || status === 501) return { kind: 'unimplemented', message: `${subject}接口未在当前固件实现` };
    if (status >= 500) return { kind: 'server', message: `${subject}读取时后端返回 ${status}` };
    return { kind: 'error', message: firstText(error?.message, `${subject}读取失败`) };
  }

  /*
   * 活动数据的时间戳是 `time_base: epoch_seconds_utc`，桶边界已由后端按
   * 路由器本地零点对齐，随响应给出 `tz_offset_minutes`（30.1 实测 480）。
   * 所以这里按该偏移把 UTC 秒折算成路由器本地时间再读各字段，
   * **不能**交给浏览器本地时区：浏览器与路由器不同区时，刻度会和后端对齐的
   * 桶边界错开，出现「今天」这一栏从 08:00 起跳的错位。
   */
  function activityParts(seconds, offsetMinutes) {
    const shifted = new Date((Math.round(firstNumber(seconds, 0)) + Math.round(firstNumber(offsetMinutes, 0)) * 60) * 1000);
    const pad = (value) => String(value).padStart(2, '0');
    return {
      year: shifted.getUTCFullYear(),
      month: pad(shifted.getUTCMonth() + 1),
      day: pad(shifted.getUTCDate()),
      hour: pad(shifted.getUTCHours()),
      minute: pad(shifted.getUTCMinutes()),
      second: pad(shifted.getUTCSeconds())
    };
  }

  function activityStamp(seconds, offsetMinutes) {
    if (!firstNumber(seconds, 0)) return '--';
    const p = activityParts(seconds, offsetMinutes);
    return `${p.year}-${p.month}-${p.day} ${p.hour}:${p.minute}:${p.second}`;
  }

  /*
   * 刻度粒度只看响应里的 `bucket_seconds`：3600 折算成小时、86400 折算成天、
   * 604800 折算成周。前端不假设某一档 range 对应哪种粒度——后端换了桶宽，
   * 刻度跟着换，页面不需要改。
   */
  function activityBucketUnit(bucketSeconds) {
    const seconds = Math.round(firstNumber(bucketSeconds, 0));
    if (seconds >= 604800) return { key: 'week', label: `${Math.round(seconds / 604800)} 周` };
    if (seconds >= 86400) return { key: 'day', label: `${Math.round(seconds / 86400)} 天` };
    if (seconds >= 3600) return { key: 'hour', label: `${Math.round(seconds / 3600)} 小时` };
    if (seconds >= 60) return { key: 'minute', label: `${Math.round(seconds / 60)} 分钟` };
    return { key: 'second', label: `${seconds} 秒` };
  }

  function activityBucketLabel(start, bucketSeconds, offsetMinutes) {
    const p = activityParts(start, offsetMinutes);
    const unit = activityBucketUnit(bucketSeconds).key;
    if (unit === 'hour' || unit === 'minute' || unit === 'second') return `${p.hour}:${p.minute}`;
    return `${p.month}-${p.day}`;
  }

  function statusMarkup(user) {
    const active = statusLabel(user) === '活跃';
    return ui.statusBadgeMarkup?.(active ? '活跃' : '已停用', active ? 'success' : 'error') || escapeHtml(active ? '活跃' : '已停用');
  }

  function permissionLabel(user) {
    return user.permissions.length ? user.permissions.join('、') : user.role === 'owner' ? '全部权限' : '--';
  }

  function permissionOptions() {
    return [...new Set(state.users.flatMap((user) => user.permissions).filter(Boolean))].sort();
  }

  function activityEndpoint(username, range, type) {
    const query = new URLSearchParams();
    if (range) query.set('range', range);
    if (type && type !== 'all') query.set('type', type);
    const suffix = query.toString();
    return `${USERS_ENDPOINT}/${encodeURIComponent(username)}/activity${suffix ? `?${suffix}` : ''}`;
  }

  function normalizeActivity(value = {}) {
    return {
      username: firstText(value.username),
      range: firstText(value.range),
      type: firstText(value.type, 'all'),
      bucketSeconds: Math.round(firstNumber(value.bucket_seconds, 0)),
      tzOffsetMinutes: Math.round(firstNumber(value.tz_offset_minutes, 0)),
      timeBase: firstText(value.time_base),
      windowStart: Math.round(firstNumber(value.window_start, 0)),
      windowEnd: Math.round(firstNumber(value.window_end, 0)),
      total: Math.round(firstNumber(value.total, 0)),
      limit: Math.round(firstNumber(value.limit, 0)),
      truncated: value.truncated === true,
      source: firstText(value.source),
      capabilities: value.capabilities && typeof value.capabilities === 'object' ? value.capabilities : {},
      buckets: asArrayOf(value.buckets).map((bucket) => ({
        start: Math.round(firstNumber(bucket.start, 0)),
        count: Math.round(firstNumber(bucket.count, 0))
      })),
      /*
       * `types[]` 的计数由后端在类型过滤**之前**算好（jmx_app_api.c:50405），
       * 正是为了选中一项后其余项不归零，所以这里原样采用，不在前端按
       * `events[]` 二次统计——events 已被过滤且被 limit 截断，统计出来必然更小。
       */
      types: asArrayOf(value.types).map((item) => ({
        id: firstText(item.id, item.name),
        name: firstText(item.name, item.id),
        count: Math.round(firstNumber(item.count, 0))
      })).filter((item) => item.id),
      events: asArrayOf(value.events).map((event) => ({
        at: Math.round(firstNumber(event.at, 0)),
        type: firstText(event.type),
        summary: firstText(event.summary),
        action: firstText(event.action),
        risk: firstText(event.risk),
        target: firstText(event.target),
        result: firstText(event.result),
        failureReason: firstText(event.failure_reason),
        sourceIp: firstText(event.source_ip),
        /*
         * 调用方提供的原文，后端明确按文本原样返回（见该字段处的注释）。
         * 渲染必须转义：当成标记渲染就把这一页变成对着管理员的存储型 XSS。
         */
        userAgent: firstText(event.user_agent)
      }))
    };
  }

  function asArrayOf(value) {
    return Array.isArray(value) ? value : [];
  }

  /*
   * 活动 Tab 的可用性判据：**实际请求这个端点的结果**。
   * 不看别的端点的能力位，也不看代码里任何写死的开关（design.md
   * Capability truth 第 1、2 条）。进入抽屉时先探一次默认档，
   * 200 → Tab 可点并渲染真实数据；404/405/501 → Tab 说明未实现；
   * 403 / 5xx / 网络失败 → Tab 仍可点，进去说明具体原因，
   * 因为这三种都不是「功能不存在」。
   */
  async function loadActivity(username, { range = state.activity.range, type = state.activity.type } = {}) {
    if (!username) return;
    const seq = state.activity.seq + 1;
    state.activity = {
      ...state.activity,
      username,
      probe: 'loading',
      error: '',
      range,
      type: type || 'all',
      seq
    };
    patchActivityPanel();
    syncActivityTab();
    try {
      const payload = await requestJson(activityEndpoint(username, range, type));
      if (!state.mounted || state.activity.seq !== seq) return;
      const data = normalizeActivity(payload);
      state.activity = {
        ...state.activity,
        probe: 'ready',
        error: '',
        /* 生效档位以后端回显为准：不带 range 时它会告诉我们默认落在哪一档。 */
        range: data.range || range,
        type: data.type || 'all',
        data
      };
    } catch (error) {
      if (!state.mounted || state.activity.seq !== seq) return;
      const classified = classifyApiFailure(error, '用户活动');
      /*
       * 后端拒收这一档（400 invalid_range）就把它从切换器里剔掉，并退回上一个
       * 已知可用的档。这样档位集合始终是后端真的接受的那一组，而不是前端的一厢情愿。
       */
      if (classified.kind === 'invalid_range') {
        const ranges = state.activity.ranges.filter((item) => item !== range);
        const fallback = state.activity.data?.range || ranges[0] || '';
        state.activity = { ...state.activity, ranges, range: fallback };
        patchActivityPanel();
        if (fallback && fallback !== range) {
          await loadActivity(username, { range: fallback, type });
          return;
        }
      }
      state.activity = { ...state.activity, probe: classified.kind, error: classified.message, data: null };
    }
    patchActivityPanel();
    syncActivityTab();
  }

  function avatarMarkup(user, large = false) {
    const initial = escapeHtml((user.displayName || user.username).slice(0, 1).toUpperCase());
    const avatarUrl = withSystemUserAvatarRevision(user.avatarUrl, state.avatarRevision);
    return `<span class="system-user-avatar${large ? ' is-large' : ''}${avatarUrl ? ' has-image' : ''}" data-system-user-avatar-for="${escapeHtml(user.username)}" data-system-user-avatar-size="${large ? 'large' : 'compact'}">${avatarUrl ? `<img src="${escapeHtml(avatarUrl)}" alt="" data-system-user-avatar-image>` : ''}<span class="system-user-avatar-fallback" aria-hidden="true">${initial}</span></span>`;
  }

  function filteredUsers() {
    const query = state.query.trim().toLowerCase();
    return state.users.filter((user) => {
      if (state.permission !== 'all' && !user.permissions.includes(state.permission)) return false;
      if (!query) return true;
      return [user.displayName, user.username, user.email, user.role, ...user.permissions, ...user.groups].join(' ').toLowerCase().includes(query);
    });
  }

  function userRow(user) {
    /*
     * 整行可点开详情（用户 2026-08-04：「点击对应用户后」）。此前只有名字那个
     * <button> 绑了 detail，点行内空白处没反应 —— 30.1 实测点表格行抽屉不打开。
     * 行上带 data-system-user-detail，行内原有的名字按钮保留（键盘可达）。
     */
    return `<tr class="system-user-row" data-system-user-id="${escapeHtml(user.id)}" tabindex="0" role="button" aria-label="${escapeHtml(`查看 ${user.displayName} 的详情`)}">
      <td><button class="system-user-name" type="button" data-system-user-detail="${escapeHtml(user.id)}">${avatarMarkup(user)}<span><strong>${escapeHtml(user.displayName)}</strong><small>${escapeHtml(user.username)}</small></span></button></td>
      <td>${statusMarkup(user)}</td>
      <td>${escapeHtml(user.email || '--')}</td>
      <td><time>${escapeHtml(formatTime(user.lastActivity))}</time></td>
      <td>${escapeHtml(user.assignments.length ? user.assignments.join('、') : '--')}</td>
      <td>${escapeHtml(roleLabel(user.role) || '--')}</td>
      <td><span class="system-user-permissions">${escapeHtml(permissionLabel(user))}</span></td>
    </tr>`;
  }

  /*
   * 控件全部收进表格工具条（用户第 9 条），页面级 header 取消；
   * 手动刷新按钮删除，数据由 startPolling() 的轮询和写操作后的读回驱动。
   */
  function renderToolbarControls() {
    const permissions = permissionOptions();
    return `<div class="system-users-toolbar-controls">
      <label class="dwrt-kit-expand-search system-users-search" data-dwrt-component="expand-search"><span class="dwrt-kit-expand-search-original-icon">${icon('search')}</span><input type="search" data-system-user-search placeholder="搜索姓名、邮箱、角色或权限" value="${escapeHtml(state.query)}"></label>
      <div class="policy-toolbar-actions system-users-toolbar-actions">
        <label class="system-users-filter dwrt-kit-field" data-dwrt-component="field"><span>管理员权限</span><select data-system-user-permission><option value="all">全部权限</option>${permissions.map((item) => `<option value="${escapeHtml(item)}" ${state.permission === item ? 'selected' : ''}>${escapeHtml(item)}</option>`).join('')}</select></label>
        <button class="policy-filter-button" type="button" data-system-user-groups>${icon('users')}<span>管理组</span></button>
        <div class="system-users-create-wrap">
          <button class="policy-create-button" type="button" data-system-user-create-menu aria-expanded="${state.createMenu ? 'true' : 'false'}">${icon('plus')}<span>新建</span>${icon('chevron')}</button>
          <div class="system-users-create-menu" ${state.createMenu ? '' : 'hidden'}>
            <button type="button" data-system-user-create ${state.capabilities.create ? '' : 'disabled'}>${icon('plus')}<span><strong>创建新用户</strong><small>添加本地管理用户</small></span></button>
            <button type="button" data-system-user-import ${state.capabilities.import ? '' : 'disabled'}>${icon('upload')}<span><strong>从 CSV 导入用户</strong><small>先校验，再由后端写入</small></span></button>
          </div>
        </div>
        <input type="file" data-system-user-import-file accept=".csv,text/csv" hidden>
      </div>
    </div>`;
  }

  /*
   * 页面级一级 Tab 条。按 design.md 规则 27：必须同时带
   * `dwrt-kit-tabs dwrt-kit-page-tabs` 两个类（只写前者会掉到 48px 紧凑档），
   * 每个按钮要有 `role="tab"` 与 `data-value`（Kit 的药丸滑块靠 data-value 定位）。
   * 页面只添加语义类 `system-users-page-tabs`，几何交给 kit，
   * 唯一的位置意图是「占满一行」——写在 CSS 里，见 system-users.css。
   */
  function pageTabsMarkup() {
    return `<nav class="dwrt-kit-tabs dwrt-kit-page-tabs system-users-page-tabs" data-dwrt-component="tabs" data-dwrt-tabs-key="system-users-main" role="tablist" aria-label="用户管理视图">`
      + `<span class="dwrt-kit-tab-pill" aria-hidden="true"></span>`
      + PAGE_TABS.map(([id, label]) => `<button class="dwrt-kit-tab ${state.pageTab === id ? 'is-active' : ''}" type="button" role="tab" data-system-users-page-tab="${id}" data-value="${id}" aria-selected="${state.pageTab === id ? 'true' : 'false'}">${escapeHtml(label)}</button>`).join('')
      + `</nav>`;
  }

  /* 当前 Tab 的正文。三个视图各自是一张卡，外层容器常驻以便只换内容。 */
  function pageTabPanelMarkup() {
    if (state.pageTab === 'groups') return renderGroupsView();
    if (state.pageTab === 'api') return renderApiKeysView();
    return renderTable();
  }

  function renderTable() {
    const users = filteredUsers();
    return `<section class="system-users-table-card dwrt-kit-table-wrap dwrt-kit-ikuai-table-wrap dwrt-kit-glass-surface">
      <div class="dwrt-kit-table-toolbar system-users-table-toolbar"><div class="dwrt-kit-table-title system-users-table-meta"><span class="dwrt-kit-table-count">${users.length} / ${state.users.length} 位用户</span><span class="${state.error ? 'is-warning' : ''}">${escapeHtml(state.loading ? '正在读取用户目录' : state.error || `数据源：${state.source}`)}</span></div>${renderToolbarControls()}</div>
      <div class="dwrt-kit-table-scroll system-users-table-scroll">
        <table class="dwrt-kit-table dwrt-kit-ikuai-table system-users-table"><thead><tr><th>姓名</th><th>状态</th><th>邮箱</th><th>最后活动</th><th>分配</th><th>角色</th><th>权限</th></tr></thead><tbody>${state.loading ? '<tr><td colspan="7" class="dwrt-kit-table-empty">正在读取用户</td></tr>' : users.length ? users.map(userRow).join('') : `<tr><td colspan="7" class="dwrt-kit-table-empty">${escapeHtml(state.query || state.permission !== 'all' ? '没有匹配的用户' : state.error || '暂无用户')}</td></tr>`}</tbody></table>
      </div>
    </section>`;
  }

  /*
   * 「组」视图。数据与能力位早就齐了（`system/user-groups` 200，capabilities 里
   * group_read / group_create / group_update 均为 true），此前只藏在
   * 工具栏「管理组」按钮弹出的抽屉里。这里把它提为一级视图。
   *
   * 表格上方不另起 `<header>`：创建按钮落在 kit 的 `.dwrt-kit-table-toolbar` 里
   * （design.md 规则 15）。抽屉入口保留不动，两条路径读同一份 state.groups。
   */
  function renderGroupsView() {
    /*
     * 能力位读**归一化之后**的名字。normalizeCapabilities() 把后端的
     * `group_create` 改成了驼峰 `groupCreate`，写成 `state.capabilities.group_create`
     * 永远是 undefined —— 按钮看起来能用，其实是靠后面那个 `create` 兜底，
     * 一旦后端只给 group_create 而不给 create，按钮就会错误地灰掉。
     */
    const canCreate = state.capabilities.groupCreate === true || state.capabilities.create === true;
    const canDelete = state.capabilities.delete === true;
    const groups = state.groups;
    const emptyText = state.capabilities.groups
      ? '还没有用户组。创建一个组，把成员的角色与权限一起管理。'
      : firstText(state.groupsError, '用户组读取失败');
    const rows = groups.length
      ? groups.map((group) => `<tr data-system-group-row="${escapeHtml(group.id || group.name)}">
          <td><div class="system-users-cell-identity"><span class="system-user-avatar">${escapeHtml(group.name.slice(0, 1).toUpperCase())}</span><span><strong>${escapeHtml(group.name)}</strong>${group.description ? `<small>${escapeHtml(group.description)}</small>` : ''}</span></div></td>
          <td>${group.userCount} 位用户</td>
          <td>${escapeHtml(groupTierCellText(group))}</td>
          <td>${escapeHtml(group.description || '--')}</td>
          <td class="system-users-cell-actions">${canDelete ? `<button class="system-user-group-remove" type="button" data-system-group-delete="${escapeHtml(group.id || group.name)}" aria-label="${escapeHtml(`删除组 ${group.name}`)}" data-dwrt-tooltip="删除组" ${state.saving ? 'disabled' : ''}>${icon('trash')}</button>` : ''}</td>
        </tr>`).join('')
      : `<tr><td colspan="5" class="dwrt-kit-table-empty">${escapeHtml(emptyText)}</td></tr>`;
    return `<section class="system-users-table-card system-users-groups-card dwrt-kit-table-wrap dwrt-kit-ikuai-table-wrap dwrt-kit-glass-surface">
      <div class="dwrt-kit-table-toolbar system-users-table-toolbar">
        <div class="dwrt-kit-table-title system-users-table-meta"><span class="dwrt-kit-table-count">${groups.length} 个组</span><span class="${state.groupsError ? 'is-warning' : ''}">${escapeHtml(state.groupsError || `数据源：${GROUPS_ENDPOINT}`)}</span></div>
        <div class="policy-toolbar-actions system-users-toolbar-actions">
          <button class="policy-create-button" type="button" data-system-group-page-new ${canCreate && !state.saving ? '' : 'disabled'} ${canCreate ? '' : 'data-dwrt-tooltip="后端未开放用户组创建"'}>${icon('plus')}<span>创建组</span></button>
        </div>
      </div>
      <div class="dwrt-kit-table-scroll system-users-table-scroll">
        <table class="dwrt-kit-table dwrt-kit-ikuai-table system-users-table system-users-groups-table"><thead><tr><th>组名称</th><th>成员</th><th>权限档</th><th>备注</th><th></th></tr></thead><tbody>${rows}</tbody></table>
      </div>
    </section>`;
  }

  /*
   * 「API 管理」视图。后端路由确实存在（`strings /usr/bin/dreamingwrt-webd` 里有
   * `/api/v1/auth/api-keys`，并有完整的 `api_keys` 表与增删改查 SQL），
   * 但它是 medium 风险：viewer 读会拿到 403。
   *
   * 所以这里严格按 probe 分档措辞——403 说「当前账号无权」，404 才说「未实现」。
   * 把两者混成一句「后端未提供」是 design.md Capability truth 明确禁止的，
   * 也会让人误以为这个功能还没做。
   */
  function renderApiKeysView() {
    const probe = state.apiKeys.probe;
    const keys = state.apiKeys.items;
    const canCreate = state.apiKeys.capabilities.create === true;
    let body;
    if (probe === 'idle' || (probe === 'loading' && !keys.length)) {
      body = `<tr><td colspan="7" class="dwrt-kit-table-empty">正在读取 API 密钥</td></tr>`;
    } else if (probe !== 'ready') {
      body = `<tr><td colspan="7" class="dwrt-kit-table-empty">${escapeHtml(state.apiKeys.error || 'API 密钥不可读')}</td></tr>`;
    } else if (!keys.length) {
      body = `<tr><td colspan="7" class="dwrt-kit-table-empty">还没有 API 密钥。创建一把密钥，让外部程序以受限权限调用接口。</td></tr>`;
    } else {
      body = keys.map((key) => `<tr data-system-api-key-row="${escapeHtml(key.id)}">
        <td><div class="system-users-cell-identity"><span><strong>${escapeHtml(key.name)}</strong><small>${escapeHtml(key.id)}</small></span></div></td>
        <td><span class="system-user-tag ${key.status === 'active' ? 'is-online' : ''}">${escapeHtml(apiKeyStatusLabel(key))}</span></td>
        <td>${escapeHtml(apiKeyTierLabel(key.tier))}</td>
        <td>${escapeHtml(key.lastUsedAt ? `${formatTime(key.lastUsedAt)}${key.lastUsedIp ? ` · ${key.lastUsedIp}` : ''}` : '从未使用')}</td>
        <td>${key.useCount}</td>
        <td>${escapeHtml(key.expiresAt ? formatTime(key.expiresAt) : '永不过期')}</td>
        <td>${escapeHtml(apiKeyAgeText(key))}</td>
      </tr>`).join('');
    }
    /*
     * 状态行说明数据来源与不可读的原因。`probe` 为 'forbidden' 时要点明是账号权限，
     * 而不是含糊的「读取失败」——用户看到后者只会以为功能坏了。
     */
    const statusText = probe === 'ready'
      ? `数据源：${API_KEYS_ENDPOINT}`
      : (state.apiKeys.error || '正在确认 API 密钥接口');
    /*
     * 更换提示只在列表读到之后出现：没读到时不知道有哪些密钥，
     * 提醒轮换就是凭空猜测。按 design.md 第 523 条，说明性文字是卡内
     * 行内文案，不另起一张浮动卡片。
     */
    const rotationHint = probe === 'ready' ? apiKeyRotationHint(keys) : '';
    return `<section class="system-users-table-card system-users-api-card dwrt-kit-table-wrap dwrt-kit-ikuai-table-wrap dwrt-kit-glass-surface">
      <div class="dwrt-kit-table-toolbar system-users-table-toolbar">
        <div class="dwrt-kit-table-title system-users-table-meta"><span class="dwrt-kit-table-count">${keys.length} 把密钥</span><span class="${probe !== 'ready' ? 'is-warning' : ''}">${escapeHtml(statusText)}</span></div>
        <div class="policy-toolbar-actions system-users-toolbar-actions">
          <button class="policy-filter-button" type="button" data-system-api-keys-refresh ${probe === 'loading' ? 'disabled' : ''}>${icon('refresh')}<span>刷新</span></button>
          <button class="policy-create-button" type="button" data-system-api-key-create ${canCreate && !state.saving ? '' : 'disabled'} ${canCreate ? '' : `data-dwrt-tooltip="${escapeHtml(apiKeyCreateBlockedReason())}"`}>${icon('plus')}<span>创建密钥</span></button>
        </div>
      </div>
      ${rotationHint ? `<div class="system-users-notice system-users-api-hint">${escapeHtml(rotationHint)}</div>` : ''}
      <div class="dwrt-kit-table-scroll system-users-table-scroll">
        <table class="dwrt-kit-table dwrt-kit-ikuai-table system-users-table system-users-api-table"><thead><tr><th>名称</th><th>状态</th><th>权限档</th><th>最后使用</th><th>调用次数</th><th>过期时间</th><th>已使用</th></tr></thead><tbody>${body}</tbody></table>
      </div>
    </section>`;
  }

  function apiKeyStatusLabel(key) {
    if (key.status === 'revoked') return '已撤销';
    if (key.status === 'expired') return '已过期';
    return '生效中';
  }

  /*
   * 密钥已存在多少天。后端 `created_at` 就够算，不再要它加 `age_days` 字段。
   * 秒/毫秒两种时间戳都可能出现（formatTime() 同样兜底），按 1e11 分界。
   */
  function apiKeyAgeDays(key) {
    const raw = Number(key?.createdAt) || 0;
    if (!raw) return 0;
    const createdMs = raw < 100000000000 ? raw * 1000 : raw;
    const days = Math.floor((Date.now() - createdMs) / 86400000);
    return days > 0 ? days : 0;
  }

  /* 建议更换的天数门槛。90 天是常见的凭据轮换周期，超过就在列表里点出来。 */
  const API_KEY_ROTATE_AFTER_DAYS = 90;

  /* 表格「已使用」列。超过门槛的追一句建议更换，提示落在有问题的那一行上。 */
  function apiKeyAgeText(key) {
    if (!key.createdAt) return '--';
    const days = apiKeyAgeDays(key);
    const text = days > 0 ? `${days} 天` : '今天创建';
    if (key.status !== 'active' || days < API_KEY_ROTATE_AFTER_DAYS) return text;
    return `${text} · 建议更换`;
  }

  /*
   * 用户 08-03 决策里点名要的两条提醒之一：**建议定期更换密钥以防泄漏**。
   *
   * 只针对还生效的密钥；已撤销/已过期的不用再提醒更换。永不过期的那批是重点，
   * 因为它没有任何自然轮换点，泄漏后会一直有效。
   */
  function apiKeyRotationHint(keys) {
    const active = keys.filter((key) => key.status === 'active');
    if (!active.length) return '';
    const neverExpires = active.filter((key) => !key.expiresAt);
    const aged = active.filter((key) => apiKeyAgeDays(key) >= API_KEY_ROTATE_AFTER_DAYS);
    if (!neverExpires.length && !aged.length) return '';
    const parts = [];
    if (neverExpires.length) parts.push(`${neverExpires.length} 把密钥永不过期`);
    if (aged.length) {
      const oldest = Math.max(...aged.map(apiKeyAgeDays));
      parts.push(`${aged.length} 把已使用超过 ${API_KEY_ROTATE_AFTER_DAYS} 天（最久 ${oldest} 天）`);
    }
    return `${parts.join('，')}。密钥一旦泄漏就等同于长期有效的登录凭据，建议定期更换：新建一把替换用的密钥、把调用方切过去，再撤销旧的。`;
  }

  /*
   * tier 是后端 `api_keys.tier` 的取值，默认 read_only。
   *
   * 只有两档：`webd_api_key_tier_parse()`（webd_api_keys.c:186）只认
   * read_only / readonly 与 control，其它取值（含 `admin`）一律返回 -1，
   * 创建会被 400 `invalid_tier` 拒掉。原先这张表写的是
   * `{ read_only, read_write, admin }`，于是 `control` 档在列表里显示成英文
   * 原文，而 read_write / admin 两个标签永远用不到。
   */
  const API_KEY_TIER_LABELS = { read_only: '只读', readonly: '只读', control: '读写控制' };

  function apiKeyTierLabel(tier) {
    return API_KEY_TIER_LABELS[tier] || tier || '只读';
  }

  /* 档位说明，出现在创建表单的选项后面，讲清这一档能做什么。 */
  const API_KEY_TIER_HINTS = {
    read_only: '只能调用读接口，拿不到任何写权限。',
    readonly: '只能调用读接口，拿不到任何写权限。',
    control: '可以调用写接口，能改配置、下发规则，泄漏后影响面等同一个管理会话。'
  };

  /*
   * 破坏性操作与 shell 在密钥通道上是**后端硬禁**，不是可勾选项。
   *
   * 08-07 那份交接单原本要求创建表单出一个 `allow_destructive` 三档开关（默认关、
   * 勾选时确认）。后端最终没有走「开关」这条路：`g_api_key_forbidden[]`
   * （webd_api_keys.c:316）把重启、关机、恢复出厂、固件刷写、备份/恢复、
   * 重置向导、内核恢复默认值整棵子树，以及 `/terminal` 与 ttyd 一并前缀屏蔽，
   * 任何档位的密钥命中都是 403 `api_key_forbidden`；文件管理器的写方法同样关着。
   *
   * 所以这里**不画那个复选框**：勾了也无法生效的开关，正是交接单第 3 条要避免的
   * 「列出来又勾不上是更糟的体验」。改为如实告知边界——用户要的「恢复出厂和重启
   * 需要特殊注意」在这条通道上由后端直接兜住，比前端确认弹窗更强。
   * 若后端日后真的放开某类破坏性路由，届时应由它下发能力位，前端再据此出选项。
   */
  const API_KEY_HARD_LIMIT_TEXT = '即便选读写控制档，密钥也永远不能重启或关机、恢复出厂、刷写固件、'
    + '恢复备份或覆盖配置，也拿不到终端/SSH 与用户和密钥自身的管理接口——这些由后端直接拒绝，'
    + '不受档位影响。这类操作请用管理员账号在界面上做。';

  /*
   * 创建表单的档位选项。**只用后端下发的 `capabilities.tiers`**；后端没下发
   * 时退回两档常量，而不是把 UI 关掉——档位枚举缺失不代表创建能力缺失。
   */
  function apiKeyTierChoices() {
    const fromBackend = state.apiKeys.capabilities.tiers || [];
    const tiers = fromBackend.length ? fromBackend : ['read_only', 'control'];
    return tiers.map((tier) => ({ value: tier, label: apiKeyTierLabel(tier), hint: API_KEY_TIER_HINTS[tier] || '' }));
  }

  /*
   * 创建按钮灰掉时的原因。能力位没到手有两种情形，措辞必须分开：
   * 列表都读不出来（403/404）与列表读到了但后端不给建。
   */
  function apiKeyCreateBlockedReason() {
    if (state.apiKeys.probe === 'forbidden') return '当前账号无权管理 API 密钥';
    if (state.apiKeys.probe === 'unimplemented') return 'API 密钥接口未在当前固件实现';
    if (state.apiKeys.probe !== 'ready') return state.apiKeys.error || '正在确认 API 密钥接口';
    /*
     * 列表读到了但能力位说不能建。后端会给出原因（创建是 high risk，仅 owner），
     * 但那句原文是英文的，界面里说中文：能拿到 `write_min_role` 就按角色说，
     * 拿不到才退回后端原话。不得再兜底成「后端未开放 API 密钥创建」——POST 路由
     * 实际是实现好的（jmx_app_api.c:63347），那句话与事实相反。
     */
    const caps = state.apiKeys.capabilities;
    if (caps.writeMinRole) return `创建密钥属于高风险操作，仅 ${caps.writeMinRole} 角色可执行`;
    if (caps.createReason) return caps.createReason;
    if (!caps.tiers.length && caps.create !== true && caps.read !== true) return '后端未下发 API 密钥能力位，创建能力未确认';
    return '当前账号无权创建 API 密钥';
  }

  /*
   * 用户详情抽屉，参照 UniFi 的用户抽屉信息层次：
   *   头像 + 显示名 + 用户名/状态  →  身份与权限  →  归属  →  凭据与时间
   * 分组小标题领起，同组内是「标签 / 值」两列表。
   *
   * 材质走 AI 抽屉那一套（用户要求「用 AI 的抽屉样式」）：壁纸层 + 玻璃层 + 内容层。
   * 这很关键 —— 原来只挂 `policy-stable-glass`，但那个类的实现是
   * `.policy-table-route-host .policy-stable-glass`，**在用户页根本不生效**，
   * 于是抽屉 `background-color: rgba(0,0,0,0)`、`backdrop-filter: none`
   * （30.1 实测），桌面壁纸直接透上来，就是截图里那种糊成一片的样子。
   */
  function drawerShell(kicker, title, body, footer, label) {
    return `<button class="policy-drawer-backdrop dwrt-kit-sheet-overlay is-open" type="button" data-system-user-close aria-label="关闭${escapeHtml(label)}"></button>`
      + `<aside class="system-users-drawer dwrt-kit-sheet is-open" aria-label="${escapeHtml(label)}">`
      + `<div class="system-users-drawer-wallpaper" aria-hidden="true"><img data-system-users-drawer-wallpaper alt=""></div>`
      + `<div class="system-users-drawer-material" aria-hidden="true"></div>`
      + `<div class="system-users-drawer-content">`
      + `<header class="dwrt-kit-sheet-header"><div><span>${escapeHtml(kicker)}</span><strong>${escapeHtml(title)}</strong></div><button class="dwrt-kit-sheet-close" type="button" data-system-user-close aria-label="关闭">×</button></header>`
      + `<div class="dwrt-kit-sheet-body system-users-drawer-body">${body}</div>`
      + (footer ? `<footer class="dwrt-kit-sheet-footer">${footer}</footer>` : '')
      + `</div></aside>`;
  }

  function detailGroup(title, rows) {
    const visible = rows.filter(([, value]) => value !== null && value !== undefined);
    if (!visible.length) return '';
    /*
     * UniFi 参照图（用户 2026-08-04 补图）的键值列表里没有分组标题：
     * 三组之间只用发丝线分隔。标题只作为可访问性标签保留，视觉上隐藏，
     * 这样屏幕阅读器仍能听到分组语义，视觉上与参照图一致。
     */
    return `<section class="system-user-detail-group" aria-label="${escapeHtml(title)}"><h3 class="system-users-visually-hidden">${escapeHtml(title)}</h3><div class="system-user-detail-list">`
      + visible.map(([label, value]) => `<div><span>${escapeHtml(label)}</span><strong>${escapeHtml(String(value))}</strong></div>`).join('')
      + `</div></section>`;
  }

  /* 凭据串。detailDrawer() 与 patchDetailTab() 都要用，抽出来免得两处算法漂移。 */
  function credentialsFor(user) {
    return [...user.credentials, ...(user.twofa ? ['OTP'] : [])].join('、') || '--';
  }

  function detailDrawer(user) {
    const credentials = credentialsFor(user);
    const tags = [
      `<span class="system-user-tag ${user.status === 'active' ? 'is-online' : ''}">${escapeHtml(statusLabel(user))}</span>`,
      user.role ? `<span class="system-user-tag is-accent">${escapeHtml(roleLabel(user.role))}</span>` : '',
      user.twofa ? '<span class="system-user-tag">双因素已启用</span>' : ''
    ].filter(Boolean).join('');
    /*
     * 设置 Tab 的草稿在这里显式播种一次，不依赖模板字面量的求值顺序。
     * detailFooterMarkup() 要读同一份草稿判断脏位，若指望
     * `${settingsTabMarkup()}` 先于 footer 执行来顺带初始化，
     * 以后调换拼接顺序就会读到空草稿、按钮永远灰着。
     */
    if (state.detailTab === 'settings') settingsDraftFor(user);
    const body = `
      <section class="system-user-profile">${avatarMarkup(user, true)}<div class="system-user-profile-identity"><strong>${escapeHtml(user.displayName)}</strong><span>${escapeHtml(user.username)}${user.email ? ` · ${escapeHtml(user.email)}` : ''}</span><div class="system-user-profile-tags">${tags}</div></div></section>
      ${detailTabsMarkup()}
      <div class="system-user-detail-panel" data-system-user-detail-panel>${detailTabBodyMarkup(user, credentials)}</div>`;
    return drawerShell('USER', user.displayName, body, detailFooterMarkup(user), '用户详情');
  }

  function detailTabBodyMarkup(user, credentials) {
    if (state.detailTab === 'settings') return settingsTabMarkup(user);
    if (state.detailTab === 'activity') return activityTabMarkup();
    return overviewTabMarkup(user, credentials);
  }

  /*
   * 详情抽屉的 Tab 条。复用 kit 的 `dwrt-kit-tabs / dwrt-kit-tab` 形制
   * （照 gateway-shadow.js:308 的既有用法），不新造材质。
   *
   * 「活动」Tab 的可用性**在运行时由目标端点自己的响应决定**，不是代码里的字面量。
   * 这里曾经写死 `false` 加「后端未提供活动时序接口」：契约当时确实 404，但 2026-08-05
   * 上线后没人回来改，页面就把已经就绪的功能说成不存在（design.md Capability truth
   * 第 1、2 条禁止的模式）。判据现在是 `state.activity.probe`：只有探测明确答
   * 「未实现」才禁用，403 / 5xx / 网络失败一律保持可点，让那一页说出真实原因——
   * 权限不足和功能不存在是两件事，混成一个灰按钮就分不出来了。
   */
  function detailTabsMarkup() {
    const probe = state.activity.probe;
    const activityUnimplemented = probe === 'unimplemented';
    const tabs = [
      ['overview', '概览', 'profile', true, ''],
      ['activity', '活动', 'activity', !activityUnimplemented, activityUnimplemented ? state.activity.error : ''],
      ['settings', '设置', 'settings', true, '']
    ];
    return `<nav class="dwrt-kit-tabs dwrt-kit-page-tabs system-user-detail-tabs" data-dwrt-component="tabs" role="tablist" aria-label="用户详情视图">`
      + `<span class="dwrt-kit-tab-pill" aria-hidden="true"></span>`
      + tabs.map(([id, label, iconName, enabled, reason]) => `<button class="dwrt-kit-tab ${state.detailTab === id ? 'is-active' : ''}" type="button" role="tab" data-system-user-tab="${id}" data-value="${id}" aria-selected="${state.detailTab === id}" ${enabled ? '' : `disabled data-dwrt-tooltip="${escapeHtml(reason)}"`} aria-label="${escapeHtml(label)}">${icon(iconName)}<span>${escapeHtml(label)}</span></button>`).join('')
      + `</nav>`;
  }

  function overviewTabMarkup(user, credentials) {
    return `<div class="system-user-detail-card">
        ${detailGroup('身份与权限', [
          ['角色', roleLabel(user.role) || '--'],
          ['权限', permissionLabel(user)],
          ['邮箱', user.email || '--']
        ])}
        ${detailGroup('归属', [
          ['用户组', user.groups.length ? user.groups.join('、') : '--'],
          ['分配', user.assignments.length ? user.assignments.join('、') : '--']
        ])}
        ${detailGroup('凭据与时间', [
          ['凭据', credentials],
          ['双因素', user.twofa ? '已启用' : '未启用'],
          ['添加时间', formatTime(user.createdAt)],
          ['最后活动', formatTime(user.lastActivity)]
        ])}
      </div>
      ${state.error ? `<div class="system-users-notice">${escapeHtml(state.error)}</div>` : ''}`;
  }

  /*
   * 「活动」Tab。外层节点常驻并带 `data-system-user-activity-panel`，
   * 因为 patchActivityPanel() 只换这一块的内容：整体 render() 会重建抽屉外壳，
   * kit 重播入场动画并丢掉滚动位置（design.md 规则 30）。
   */
  function activityTabMarkup() {
    return `<div class="system-user-activity" data-system-user-activity-panel>${activityPanelInnerMarkup()}</div>`;
  }

  function activityPanelInnerMarkup() {
    const activity = state.activity;
    if (activity.probe === 'idle') return `<div class="system-users-empty">正在确认活动接口</div>`;
    if (activity.probe === 'loading' && !activity.data) return `<div class="system-users-empty">正在读取活动记录</div>`;
    if (activity.probe !== 'ready' && activity.probe !== 'loading') {
      /* 分类文案直接用，不套一句通用「加载失败」把 403 和 404 揉成一种。 */
      return `${activityRangeMarkup()}<div class="system-users-empty">${escapeHtml(activity.error || '活动记录不可用')}</div>`;
    }
    const data = activity.data;
    if (!data) return `<div class="system-users-empty">正在读取活动记录</div>`;
    return `${activityRangeMarkup()}${activityWindowMarkup(data)}${activityChartMarkup(data)}${activityTypesMarkup(data)}${activityEventsMarkup(data)}`;
  }

  /*
   * 档位按钮的标签就是后端的 range token 本身（`1d` / `1w` …），不另造中文档名：
   * 每一档的真实含义（窗口跨度与刻度）由响应里的 window_start/window_end 与
   * bucket_seconds 说明，写在下面那行说明里。集合来自 state.activity.ranges，
   * 被后端 400 拒过的档已被剔除。
   */
  function activityRangeMarkup() {
    const activity = state.activity;
    if (!activity.ranges.length) return '';
    return `<div class="system-user-activity-ranges" role="group" aria-label="活动时间范围">`
      + activity.ranges.map((range) => `<button class="system-user-activity-range ${activity.range === range ? 'is-active' : ''}" type="button" data-system-user-activity-range="${escapeHtml(range)}" aria-pressed="${activity.range === range}" ${activity.probe === 'loading' ? 'disabled' : ''}>${escapeHtml(range)}</button>`).join('')
      + `</div>`;
  }

  function activityWindowMarkup(data) {
    const unit = activityBucketUnit(data.bucketSeconds);
    const window = `${activityStamp(data.windowStart, data.tzOffsetMinutes)} 至 ${activityStamp(data.windowEnd, data.tzOffsetMinutes)}`;
    const offsetHours = data.tzOffsetMinutes / 60;
    const zone = `UTC${offsetHours >= 0 ? '+' : ''}${Number.isInteger(offsetHours) ? offsetHours : offsetHours.toFixed(1)}`;
    return `<div class="system-user-activity-window"><span>窗口 ${escapeHtml(window)}（${escapeHtml(zone)}）</span><span>刻度 ${escapeHtml(unit.label)} · 共 ${data.total} 条 · 来源 ${escapeHtml(data.source || '--')}</span></div>`;
  }

  /*
   * 直方图用 CSS 条形，高度按桶内计数占最大值的比例。不手写 viewBox +
   * preserveAspectRatio="none"（design.md 规则 14）：那样刻度文字会跟着非等比拉伸。
   * 桶数最多 31，条形交给 flex 均分，容器有固定高度，因此不依赖图表库。
   */
  function activityChartMarkup(data) {
    if (!data.buckets.length) return `<div class="system-users-empty">这段窗口内没有活动记录</div>`;
    const max = data.buckets.reduce((peak, bucket) => Math.max(peak, bucket.count), 0);
    const bars = data.buckets.map((bucket) => {
      const label = activityBucketLabel(bucket.start, data.bucketSeconds, data.tzOffsetMinutes);
      const ratio = max > 0 ? bucket.count / max : 0;
      const title = `${activityStamp(bucket.start, data.tzOffsetMinutes)} · ${bucket.count} 条`;
      return `<i style="--bar: ${(ratio * 100).toFixed(2)}%" title="${escapeHtml(title)}" aria-label="${escapeHtml(title)}"></i>`;
    }).join('');
    /*
     * 刻度只标首、中、尾三处。31 个桶全标在 411px 宽的抽屉里必然叠字，
     * 逐桶的精确时间已经在条形的 title 上。
     */
    const ticks = [0, Math.floor((data.buckets.length - 1) / 2), data.buckets.length - 1]
      .filter((index, position, list) => index >= 0 && list.indexOf(index) === position)
      .map((index) => activityBucketLabel(data.buckets[index].start, data.bucketSeconds, data.tzOffsetMinutes));
    return `<section class="system-user-activity-chart" aria-label="活动分布">
        <div class="system-user-activity-bars">${bars}</div>
        <div class="system-user-activity-ticks">${ticks.map((tick) => `<span>${escapeHtml(tick)}</span>`).join('')}</div>
        <div class="system-user-activity-peak">峰值 ${max} 条 / ${escapeHtml(activityBucketUnit(data.bucketSeconds).label)}</div>
      </section>`;
  }

  /* 计数一律用后端给的（过滤前统计），所以选中一项后其余项不会归零。 */
  function activityTypesMarkup(data) {
    if (!data.types.length) return '';
    const total = data.types.reduce((sum, item) => sum + item.count, 0);
    const chips = [{ id: 'all', name: '全部', count: total }, ...data.types];
    return `<div class="system-user-activity-types" role="group" aria-label="活动类型">`
      + chips.map((item) => `<button class="system-user-activity-type ${data.type === item.id || (data.type === 'all' && item.id === 'all') ? 'is-active' : ''}" type="button" data-system-user-activity-type="${escapeHtml(item.id)}" aria-pressed="${data.type === item.id}" ${state.activity.probe === 'loading' ? 'disabled' : ''}>${escapeHtml(item.name)}<small>${item.count}</small></button>`).join('')
      + `</div>`;
  }

  function activityEventsMarkup(data) {
    if (!data.events.length) return `<div class="system-users-empty">这段窗口内没有${data.type && data.type !== 'all' ? `「${escapeHtml(data.type)}」类型的` : ''}活动记录</div>`;
    const rows = data.events.map((event) => {
      const meta = [event.type, event.action, event.sourceIp].filter(Boolean).join(' · ');
      const outcome = [event.result, event.failureReason].filter(Boolean).join('：');
      return `<li class="system-user-activity-event">
          <span class="system-user-activity-event-time">${escapeHtml(activityStamp(event.at, data.tzOffsetMinutes))}</span>
          <span class="system-user-activity-event-body">
            <strong>${escapeHtml(event.summary || event.action || '--')}</strong>
            <small>${escapeHtml(meta)}</small>
            ${event.target ? `<small>目标 ${escapeHtml(event.target)}</small>` : ''}
            ${outcome ? `<small>${escapeHtml(outcome)}</small>` : ''}
            ${event.userAgent ? `<small class="system-user-activity-event-agent">${escapeHtml(event.userAgent)}</small>` : ''}
          </span>
          ${event.risk ? `<span class="system-user-tag">${escapeHtml(event.risk)}</span>` : ''}
        </li>`;
    }).join('');
    /* 截断是后端的 limit 行为（truncated），如实说明而不是假装这就是全部。 */
    const note = data.truncated ? `<div class="system-user-activity-note">仅显示最近 ${data.events.length} 条，窗口内共 ${data.total} 条</div>` : '';
    return `<section class="system-user-activity-timeline" aria-label="活动记录"><ul>${rows}</ul>${note}</section>`;
  }

  function settingsDraftFor(user) {
    if (state.settingsDraft && state.settingsDraft.id === user.id) return state.settingsDraft;
    state.settingsDraft = {
      id: user.id,
      username: user.username,
      display_name: user.displayName,
      email: user.email,
      role: user.role,
      status: user.status === 'active' ? 'active' : 'disabled',
      password: '',
      permissions: [...user.permissions],
      /*
       * 两项新字段的草稿。初值取用户对象上的真实值，读不到就落到「未设置」，
       * 而不是 false / 0 —— 见 firstBool / firstOptionalNumber 的注释。
       */
      apiKeyCreateDenied: user.apiKeyCreateDenied,
      passwordRotateDays: user.passwordRotateDays
    };
    return state.settingsDraft;
  }

  /*
   * 周期性改密的候选周期。这是**候选**，不是后端声明：后端目前没有这一列，
   * 也没有下发可选周期枚举。能力位为真时若后端同时给了 `password_rotate_choices`，
   * 以后端的为准；否则用这份常见周期，并在提交前由后端校验。
   */
  const PASSWORD_ROTATE_CHOICES = [
    ['0', '不强制'],
    ['30', '每 30 天'],
    ['60', '每 60 天'],
    ['90', '每 90 天'],
    ['180', '每 180 天'],
    ['365', '每 365 天']
  ];

  /*
   * 「安全策略」段：单用户级 API-Key 禁令 + 周期性改密。
   *
   * 这两项都按 design.md「能力门 tab」那条的判据处理——**填进去有地方存吗**。
   * 后端目前两样都没有：`web_users` 没有 `api_key_create_denied`，也没有
   * `password_rotate_days` / `password_changed_at`；`webd_directory_user_update()`
   * 只 COALESCE display_name / email / role / status / permissions / assignments /
   * password_hash 这几列，多给的键会被静默丢弃。所以能力位未确认时这一段
   * **只陈述缺口，不放任何可提交的控件**；后端补上 capability 后控件自动出现，
   * 不需要再改这里的判定。
   */
  function securityPolicySectionMarkup(user) {
    const draft = settingsDraftFor(user);
    const canUpdate = state.capabilities.update === true;
    const denyCap = state.capabilities.apiKeyDenyPerUser;
    const rotateCap = state.capabilities.passwordRotation;
    const rows = [];

    if (denyCap === true) {
      const denied = draft.apiKeyCreateDenied === true;
      rows.push(`<label class="system-user-policy-row">
        <input type="checkbox" data-system-user-setting-toggle="apiKeyCreateDenied" ${denied ? 'checked' : ''} ${canUpdate ? '' : 'disabled'}>
        <span>禁止该用户创建 API 密钥<small>勾选后这个账号在「API 管理」里不能再新建密钥；它已经创建的密钥不受影响，需要停用请逐把撤销。</small></span>
      </label>`);
    } else {
      rows.push(`<div class="system-user-policy-gap">${escapeHtml(apiKeyDenyGapText(denyCap))}</div>`);
    }

    if (rotateCap === true) {
      const choices = passwordRotateChoices();
      const current = draft.passwordRotateDays === undefined ? '0' : String(draft.passwordRotateDays);
      rows.push(`<label class="is-wide dwrt-kit-field" data-dwrt-component="field"><span>周期性修改密码<small>到期后该用户下次登录必须先改密码，流程与新用户首次登录一致：输入旧密码、新密码并确认。</small></span>
        <select data-system-user-setting="passwordRotateDays" ${canUpdate ? '' : 'disabled'}>${choices.map(([value, label]) => `<option value="${escapeHtml(value)}" ${current === value ? 'selected' : ''}>${escapeHtml(label)}</option>`).join('')}</select></label>`);
      rows.push(`<div class="system-user-policy-note">${escapeHtml(passwordRotateStatusText(user))}</div>`);
    } else {
      rows.push(`<div class="system-user-policy-gap">${escapeHtml(passwordRotationGapText(rotateCap))}</div>`);
    }

    return `<section class="system-user-detail-card system-user-settings-card" aria-label="安全策略">
      <h3 class="system-user-settings-legend">安全策略</h3>
      <div class="system-users-form system-user-policy-form">${rows.join('')}</div>
    </section>`;
  }

  /* 后端下发周期枚举时以它为准，否则用本地候选。 */
  function passwordRotateChoices() {
    const fromBackend = state.capabilities.passwordRotateChoices;
    if (Array.isArray(fromBackend) && fromBackend.length) {
      return fromBackend
        .map((item) => [String(item?.value ?? item ?? ''), firstText(item?.label, item?.value, item)])
        .filter(([value]) => value !== '');
    }
    return PASSWORD_ROTATE_CHOICES;
  }

  /*
   * 当前轮换状态。`password_changed_at` 缺失时只说「后端未回上次改密时间」，
   * 不拿 created_at 顶替——那会算出一个看着精确、其实错误的到期日。
   */
  function passwordRotateStatusText(user) {
    const days = Number(user.passwordRotateDays || 0);
    if (user.passwordMustChange === true) return '该用户已被标记为下次登录必须改密码。';
    if (!days) return '当前未设置强制周期，密码不会自动到期。';
    if (!user.passwordChangedAt) return `已设置每 ${days} 天强制更换，但后端未回上次改密时间，无法在此推算到期日。`;
    const dueAt = user.passwordChangedAt + days * 86400;
    const remain = Math.ceil((dueAt - Date.now() / 1000) / 86400);
    if (remain <= 0) return `已超过 ${days} 天未改密码，下次登录会被要求更换。`;
    return `上次改密 ${formatTime(user.passwordChangedAt)}，还有 ${remain} 天到期。`;
  }

  /* 能力位三态各自措辞：false 是后端明确说没有，undefined 是能力源没给这个键。 */
  function apiKeyDenyGapText(cap) {
    if (cap === false) return '后端当前未开放「按用户禁止创建 API 密钥」，因此这里不提供开关。已提交交接单请求该能力。';
    return '「按用户禁止创建 API 密钥」尚无后端存储与能力声明（web_users 无对应列，用户 PATCH 也不接受该字段），所以这里不放一个存不进去的开关。已提交交接单请求该合同。';
  }

  function passwordRotationGapText(cap) {
    if (cap === false) return '后端当前未开放「周期性修改密码」，因此这里不提供周期选择。已提交交接单请求该能力。';
    return '「周期性修改密码」尚无后端存储与能力声明（web_users 无 password_rotate_days / password_changed_at，登录也没有强制改密流程），所以这里不放一个存不进去的周期选择。已提交交接单请求该合同。';
  }

  function roleChoices() {
    /*
     * 角色下拉用 /api/v1/system/user-roles 的真实角色列表，不硬编码。
     * 后端 `webd_role_ok()`（jmx_app_api.c:2816）只接受 owner/admin/operator/viewer/user，
     * 接口读不到时才退回这五个内置值——那也不是猜的，是后端校验函数的原文。
     */
    const roles = state.roles.map((role) => firstText(role.id, role.name, role)).filter(Boolean);
    return roles.length ? roles : ['owner', 'admin', 'operator', 'viewer', 'user'];
  }

  function roleLabel(role) {
    return ({ owner: '设备所有者', admin: '管理员', operator: '操作员', viewer: '只读用户', user: '用户' })[role] || role;
  }

  /*
   * 「设置」Tab：按 UniFi 参照图的两卡结构，但字段集取本项目后端的可写列。
   *
   * 与参照图故意不一致的地方，逐条都是有依据的（交接单字段映射表）：
   * - First/Last Name 不拆：后端只有 display_name 一列，拆了保存后回读必然不一致。
   * - 不放 Admin 复选框：它和角色下拉是同一件事，两个控件会互相打架。
   * - 不放 Employee ID：后端没有这一列，控件存不进去。
   * - Onboard Date 只读：后端只有 created_at，且 PATCH 不接受它。
   * - 权限不是参照图那两个 `Full Management` 下拉，而是后端 permissions 白名单
   *   （webd_directory_permissions_ok()，11 个合法值、上限 16 项）的多选。
   *   这一维度后端**确实独立可写**，所以按交接单的条件它可以提供。
   */
  function settingsTabMarkup(user) {
    const draft = settingsDraftFor(user);
    const canUpdate = state.capabilities.update === true;
    const roles = roleChoices();
    const dirty = settingsDirtyFields(user).length > 0;
    const basic = `<section class="system-user-detail-card system-user-settings-card" aria-label="基本信息">
      <h3 class="system-user-settings-legend">基本信息</h3>
      <div class="system-users-form">
        <label class="is-wide"><span>显示名称</span><input data-system-user-setting="display_name" value="${escapeHtml(draft.display_name || '')}" maxlength="128" autocomplete="off" ${canUpdate ? '' : 'disabled'}></label>
        <label class="is-wide"><span>邮箱</span><input data-system-user-setting="email" type="email" value="${escapeHtml(draft.email || '')}" autocomplete="off" ${canUpdate ? '' : 'disabled'}></label>
      </div>
      <div class="system-user-detail-list system-user-settings-readonly">
        <div><span>用户名</span><strong>${escapeHtml(user.username)}<small>不可改名</small></strong></div>
        <div><span>添加时间</span><strong>${escapeHtml(formatTime(user.createdAt))}</strong></div>
      </div>
    </section>`;
    const account = `<section class="system-user-detail-card system-user-settings-card" aria-label="账号与权限">
      <h3 class="system-user-settings-legend">账号与权限</h3>
      <div class="system-users-form">
        <label class="dwrt-kit-field" data-dwrt-component="field"><span>角色</span><select data-system-user-setting="role" ${canUpdate ? '' : 'disabled'}>${roles.map((role) => `<option value="${escapeHtml(role)}" ${draft.role === role ? 'selected' : ''}>${escapeHtml(roleLabel(role))}</option>`).join('')}</select></label>
        <label class="dwrt-kit-field" data-dwrt-component="field"><span>状态</span><select data-system-user-setting="status" ${canUpdate ? '' : 'disabled'}><option value="active" ${draft.status === 'active' ? 'selected' : ''}>活跃</option><option value="disabled" ${draft.status === 'disabled' ? 'selected' : ''}>已停用</option></select></label>
        <label class="is-wide"><span>重置密码<small>留空表示不修改，至少 8 位</small></span><input data-system-user-setting="password" type="password" value="${escapeHtml(draft.password || '')}" autocomplete="new-password" placeholder="留空则不改动" ${canUpdate ? '' : 'disabled'}></label>
      </div>
      <fieldset class="system-user-permission-set" ${canUpdate ? '' : 'disabled'}>
        <legend>权限项<small>最多 16 项</small></legend>
        ${SYSTEM_USER_PERMISSION_CHOICES.map(([value, label]) => `<label class="system-user-permission-choice"><input type="checkbox" data-system-user-permission-toggle="${escapeHtml(value)}" ${draft.permissions.includes(value) ? 'checked' : ''} ${canUpdate ? '' : 'disabled'}><span>${escapeHtml(label)}<small>${escapeHtml(value)}</small></span></label>`).join('')}
      </fieldset>
    </section>`;
    const hint = canUpdate ? '' : '<div class="system-users-notice">当前账号没有修改用户的权限，表单为只读。</div>';
    const notice = state.settingsError ? `<div class="system-users-notice">${escapeHtml(state.settingsError)}</div>` : '';
    /* 脏标记常驻 DOM、靠 hidden 开关：syncSettingsFooter() 不整体重绘，节点必须一直在。 */
    return `${basic}${account}${securityPolicySectionMarkup(user)}${hint}${notice}`
      + `<div class="system-user-settings-dirty" role="status" ${dirty && canUpdate ? '' : 'hidden'}>有未保存的修改</div>`;
  }

  /*
   * 只提交真的改了的字段。后端 UPDATE 用 COALESCE，未出现的键保持原值，
   * 所以最小化 body 既避免无谓写库，也避开 last_manager_protected 这类
   * 只在字段真的出现时才触发的保护逻辑。
   */
  function settingsDirtyFields(user) {
    const draft = settingsDraftFor(user);
    const fields = [];
    if ((draft.display_name || '') !== (user.displayName || '')) fields.push('display_name');
    if ((draft.email || '') !== (user.email || '')) fields.push('email');
    if ((draft.role || '') !== (user.role || '')) fields.push('role');
    if ((draft.status || '') !== (user.status === 'active' ? 'active' : 'disabled')) fields.push('status');
    if (String(draft.password || '')) fields.push('password');
    const before = [...user.permissions].sort().join(',');
    const after = [...draft.permissions].sort().join(',');
    if (before !== after) fields.push('permissions');
    /*
     * 两项新字段只在**后端声明了对应能力**时才参与脏判定。否则它们的草稿值
     * 永远等于读回来的 undefined，不会污染保存条，也不会把一个后端会丢弃的键
     * 塞进 PATCH body。
     */
    if (state.capabilities.apiKeyDenyPerUser === true
      && (draft.apiKeyCreateDenied === true) !== (user.apiKeyCreateDenied === true)) fields.push('api_key_create_denied');
    if (state.capabilities.passwordRotation === true
      && Number(draft.passwordRotateDays || 0) !== Number(user.passwordRotateDays || 0)) fields.push('password_rotate_days');
    return fields;
  }

  function detailFooterMarkup(user) {
    if (state.detailTab !== 'settings') return '';
    const canUpdate = state.capabilities.update === true;
    const dirty = settingsDirtyFields(user).length > 0;
    return `<button class="policy-secondary" type="button" data-system-user-settings-reset ${dirty && !state.saving ? '' : 'disabled'}>还原</button>`
      + `<button class="policy-primary" type="button" data-system-user-settings-save ${canUpdate && dirty && !state.saving ? '' : 'disabled'}>${state.saving ? '正在保存' : '保存修改'}</button>`;
  }

  function createDrawer() {
    const roles = state.roles.length ? state.roles.map((role) => firstText(role.id, role.name, role)) : ['admin', 'operator', 'viewer'];
    const body = `<div class="system-users-form"><label><span>用户名</span><input data-user-draft="username" value="${escapeHtml(state.draft.username || '')}" autocomplete="off"></label><label><span>显示名称</span><input data-user-draft="display_name" value="${escapeHtml(state.draft.display_name || '')}"></label><label><span>邮箱</span><input data-user-draft="email" type="email" value="${escapeHtml(state.draft.email || '')}"></label><label class="dwrt-kit-field" data-dwrt-component="field"><span>角色</span><select data-user-draft="role">${roles.map((role) => `<option value="${escapeHtml(role)}" ${(state.draft.role || 'admin') === role ? 'selected' : ''}>${escapeHtml(role)}</option>`).join('')}</select></label><label class="is-wide"><span>初始密码</span><input data-user-draft="password" type="password" value="${escapeHtml(state.draft.password || '')}" autocomplete="new-password"></label></div>${state.notice ? `<div class="system-users-notice">${escapeHtml(state.notice)}</div>` : ''}`;
    const footer = `<button class="policy-secondary" type="button" data-system-user-close>取消</button><button class="policy-primary" type="button" data-system-user-save ${state.capabilities.create && state.draft.username && state.draft.password && !state.saving ? '' : 'disabled'}>${state.saving ? '正在保存' : '创建用户'}</button>`;
    return drawerShell('CREATE USER', '创建新用户', body, footer, '创建用户');
  }

  /* 创建密钥表单的默认值。tier 取后端下发的第一档，通常是只读，即最小权限。 */
  function apiKeyDraftDefaults() {
    const choices = apiKeyTierChoices();
    return { name: '', tier: choices[0]?.value || 'read_only', expires: '90', allow_ips: '' };
  }

  function apiKeyDraft() {
    if (!state.apiKeys.draft) state.apiKeys.draft = apiKeyDraftDefaults();
    return state.apiKeys.draft;
  }

  /*
   * 有效期下拉的候选。后端只收一个绝对时间戳 `expires_at`（秒），
   * 这里把天数换算过去；「永不过期」提交 0，后端语义就是不过期。
   */
  const API_KEY_EXPIRY_CHOICES = [
    ['30', '30 天'],
    ['90', '90 天'],
    ['180', '180 天'],
    ['365', '365 天'],
    ['0', '永不过期']
  ];

  /*
   * 创建 API 密钥抽屉。
   *
   * 这里承载用户 08-03 决策要求的两条告知：**数据安全与破坏性操作风险**，
   * 以及**建议定期更换以防泄漏**。原文见
   * todo/Filed/2026-08-03/Handoff/Acceptance-to-Backend-api-key-decisions-approved.md：
   * 写操作完全开放、不设额外闸门，代价由前端如实讲清，而不是靠拦住用户。
   *
   * 字段逐个对齐后端 `webd_api_keys_create_response()`（jmx_app_api.c:51341）真的
   * 会读的键：name / tier / expires_at / allow_ips。`scope_json` 后端虽然接受，
   * 但没有可选值枚举可依据，这里不画一个猜出来的输入框（design.md 第 954 条）。
   */
  function apiKeyCreateDrawer() {
    const created = state.apiKeys.created;
    if (created) return apiKeyCreatedDrawer(created);
    const draft = apiKeyDraft();
    const choices = apiKeyTierChoices();
    const activeTier = choices.find((choice) => choice.value === draft.tier) || choices[0];
    const risky = activeTier && activeTier.value !== 'read_only' && activeTier.value !== 'readonly';
    const body = `
      <div class="system-users-notice system-users-api-risk">
        密钥是一段可以绕过登录直接调用接口的长期凭据。持有它的程序拥有所选权限档内的全部能力，
        写档还能改配置、下发规则、删除数据，这些操作没有二次确认，出问题也无法自动回滚。
        只发给确实需要的程序，按最小权限选档，并记录它保存在哪里。
      </div>
      <div class="system-users-form">
        <label class="is-wide"><span>名称<small>用于日后辨认这把密钥属于哪个调用方</small></span><input data-api-key-draft="name" value="${escapeHtml(draft.name || '')}" maxlength="64" autocomplete="off" placeholder="例如 monitoring-exporter"></label>
        <label class="dwrt-kit-field" data-dwrt-component="field"><span>权限档</span><select data-api-key-draft="tier">${choices.map((choice) => `<option value="${escapeHtml(choice.value)}" ${draft.tier === choice.value ? 'selected' : ''}>${escapeHtml(choice.label)}</option>`).join('')}</select></label>
        <label class="dwrt-kit-field" data-dwrt-component="field"><span>有效期</span><select data-api-key-draft="expires">${API_KEY_EXPIRY_CHOICES.map(([value, label]) => `<option value="${value}" ${String(draft.expires) === value ? 'selected' : ''}>${escapeHtml(label)}</option>`).join('')}</select></label>
        <label class="is-wide"><span>来源 IP 限制<small>逗号分隔的地址或 CIDR，留空表示不限制来源</small></span><input data-api-key-draft="allow_ips" value="${escapeHtml(draft.allow_ips || '')}" autocomplete="off" placeholder="例如 192.168.30.0/24,192.168.30.9"></label>
      </div>
      ${activeTier?.hint ? `<div class="system-users-api-tier-hint${risky ? ' is-risky' : ''}">${escapeHtml(activeTier.label)}：${escapeHtml(activeTier.hint)}</div>` : ''}
      <div class="system-users-api-tier-hint">${escapeHtml(API_KEY_HARD_LIMIT_TEXT)}</div>
      <div class="system-users-api-rotate-hint">
        ${String(draft.expires) === '0'
          ? '选了永不过期就没有自然的轮换点，一旦泄漏会一直有效。建议自行安排定期更换：新建一把、切走调用方、撤销旧的。'
          : `到期后密钥自动失效。即便如此也建议定期更换，避免一把密钥长期在外流转；超过 ${API_KEY_ROTATE_AFTER_DAYS} 天的密钥会在列表里标出来。`}
      </div>
      ${state.apiKeys.notice ? `<div class="system-users-notice">${escapeHtml(state.apiKeys.notice)}</div>` : ''}`;
    const ready = Boolean(String(draft.name || '').trim()) && !state.saving;
    const footer = `<button class="policy-secondary" type="button" data-system-user-close>取消</button>`
      + `<button class="policy-primary" type="button" data-system-api-key-save ${ready ? '' : 'disabled'}>${state.saving ? '正在创建' : '创建密钥'}</button>`;
    return drawerShell('CREATE API KEY', '创建 API 密钥', body, footer, '创建 API 密钥');
  }

  /*
   * 创建成功后的明文展示。后端 `plaintext_shown_once: true`，明文不落库、不进日志、
   * 关掉这一屏就再也读不到，所以必须把「现在复制」说透。
   */
  function apiKeyCreatedDrawer(created) {
    const body = `
      <div class="system-users-notice system-users-api-risk">
        这是唯一一次显示密钥明文。它不会落库、也无法再次读取，现在复制并存进你的密钥管理工具；
        丢了只能撤销这把、重新创建一把。把它当密码对待：不要写进代码仓库、聊天记录或工单。
      </div>
      <div class="system-user-detail-list">
        <div><span>名称</span><strong>${escapeHtml(created.name || '')}</strong></div>
        <div><span>密钥 ID</span><strong>${escapeHtml(created.keyId || '')}</strong></div>
        <div><span>权限档</span><strong>${escapeHtml(apiKeyTierLabel(created.tier))}</strong></div>
        <div><span>过期时间</span><strong>${escapeHtml(created.expiresAt ? formatTime(created.expiresAt) : '永不过期')}</strong></div>
      </div>
      <div class="system-users-api-plaintext"><code data-system-api-key-plaintext>${escapeHtml(created.plaintext || '')}</code></div>
      <div class="system-users-api-tier-hint">${escapeHtml(API_KEY_HARD_LIMIT_TEXT)}</div>
      ${created.expiresAt ? '' : '<div class="system-users-api-rotate-hint">这把密钥永不过期，请自行安排定期更换，防止长期在外流转后泄漏。</div>'}
      ${state.apiKeys.notice ? `<div class="system-users-notice">${escapeHtml(state.apiKeys.notice)}</div>` : ''}`;
    const footer = `<button class="policy-secondary" type="button" data-system-api-key-copy>复制密钥</button>`
      + `<button class="policy-primary" type="button" data-system-user-close>我已保存</button>`;
    return drawerShell('API KEY CREATED', '密钥已创建', body, footer, '密钥已创建');
  }

  /*
   * 管理组抽屉。
   *
   * 「创建组」原先是硬写的 `disabled`，没有任何依据 —— 而后端
   * `GET /api/v1/system/user-groups` 的 capabilities 实测就是
   * `group_create: true, group_update: true, delete: true`（30.1，2026-08-04）。
   * 这就是用户说的「管理组目前也是不能正常创建组」：不是后端没实现，是前端把按钮钉死了。
   * 现在按能力位判定，并提供真正的新建表单（名称 + 备注）。
   */
  function groupsDrawer() {
    /* 同 renderGroupsView()：能力位读归一化后的驼峰名，下划线名永远是 undefined。 */
    const canCreate = state.capabilities.groupCreate === true || state.capabilities.create === true;
    const creating = Boolean(state.groupDraftOpen);
    const name = String(state.groupDraft?.name || '');
    const list = state.groups.length
      ? `<div class="system-user-group-list">${state.groups.map((group) => `<div><span class="system-user-avatar">${escapeHtml(group.name.slice(0, 1).toUpperCase())}</span><span><strong>${escapeHtml(group.name)}</strong><small>${group.userCount} 位用户</small></span>${state.capabilities.delete === true ? `<button class="system-user-group-remove" type="button" data-system-group-delete="${escapeHtml(group.id || group.name)}" aria-label="${escapeHtml(`删除组 ${group.name}`)}" data-dwrt-tooltip="删除组" ${state.saving ? 'disabled' : ''}>${icon('trash')}</button>` : ''}</div>`).join('')}</div>`
      : `<div class="system-users-empty">${escapeHtml(state.capabilities.groups ? '还没有用户组。创建一个组，把成员的角色与权限一起管理。' : firstText(state.groupsError, '用户组读取失败'))}</div>`;
    const form = creating
      ? `<section class="system-user-detail-group"><h3>新建组</h3><div class="system-users-form"><label class="is-wide"><span>组名称</span><input data-system-group-draft="name" value="${escapeHtml(name)}" placeholder="例如 网络运维" autocomplete="off"></label><label class="is-wide"><span>备注</span><input data-system-group-draft="description" value="${escapeHtml(state.groupDraft?.description || '')}" placeholder="可选"></label>${groupTierFormMarkup()}</div></section>`
      : '';
    const body = `${list}${form}${state.notice ? `<div class="system-users-notice">${escapeHtml(state.notice)}</div>` : ''}`;
    const footer = creating
      ? `<button class="policy-secondary" type="button" data-system-group-cancel>取消</button><button class="policy-primary" type="button" data-system-group-save ${canCreate && name.trim() && !state.saving ? '' : 'disabled'}>${state.saving ? '正在创建' : '创建组'}</button>`
      : `<button class="policy-primary" type="button" data-system-group-new ${canCreate && !state.saving ? '' : 'disabled'} ${canCreate ? '' : 'title="后端未开放用户组创建"'}>创建组</button>`;
    return drawerShell('USER GROUPS', '管理组', body, footer, '管理用户组');
  }

  /*
   * 组权限档。
   *
   * 每一档的 `permissions` 都取自后端 `webd_directory_permissions_ok()` 的白名单
   * （SYSTEM_USER_PERMISSION_CHOICES 那 11 项），不是自造的权限名——档位只是这些
   * 真实权限项的预设组合，所以后端一旦支持组级权限，这些值可以直接落库。
   * 「自定义」档不预设组合，由使用者逐项勾选，对应用户 08-09 的要求
   * 「给一些档位选择，然后外加一个自定义档」。
   */
  const GROUP_PERMISSION_TIERS = [
    ['readonly', '只读', '只能查看，不能改任何配置。', ['read']],
    ['operator', '运维', '可做低风险日常操作，不能改高风险配置。', ['read', 'write.low']],
    ['admin', '管理', '可改常规与中风险配置，不含高风险动作。', ['read', 'write.low', 'write.medium']],
    ['full', '完全控制', '包含高风险写入，能力接近拥有者。', ['read', 'write.low', 'write.medium', 'write.high']],
    ['custom', '自定义', '逐项勾选权限，不套用预设组合。', null]
  ];

  /* 后端下发档位枚举时以它为准（含它自己的 permissions 组合），否则用本地预设。 */
  function groupTierChoices() {
    const fromBackend = state.capabilities.groupPermissionTiers;
    if (Array.isArray(fromBackend) && fromBackend.length) {
      return fromBackend.map((tier) => [
        firstText(tier.id, tier.value),
        firstText(tier.label, tier.name, tier.id),
        firstText(tier.hint, tier.description),
        Array.isArray(tier.permissions) ? tier.permissions : null
      ]).filter(([value]) => value);
    }
    return GROUP_PERMISSION_TIERS;
  }

  function groupTierLabel(tier) {
    const found = groupTierChoices().find(([value]) => value === String(tier || ''));
    return found ? found[1] : String(tier || '');
  }

  /*
   * 组权限档表单段。判据同 securityPolicySectionMarkup()：**填进去有地方存吗**。
   * `web_user_groups` 目前只有 id / name / description / created_at / updated_at
   * （30.1 实测 schema），组写入 `webd_directory_group_write()` 也只读
   * name / description / members[]，多给的键会被静默丢弃。所以能力位未确认时
   * 这一段只陈述缺口，不放可提交的控件；后端补上 capability 后控件自动出现。
   */
  function groupTierFormMarkup() {
    const cap = state.capabilities.groupPermissionTier;
    if (cap !== true) {
      return `<div class="system-user-policy-gap">${escapeHtml(groupTierGapText(cap))}</div>`;
    }
    const choices = groupTierChoices();
    const draft = state.groupDraft || {};
    const current = firstText(draft.permissionTier, choices[0]?.[0]);
    const active = choices.find(([value]) => value === current);
    const isCustom = active && active[3] === null;
    const selected = Array.isArray(draft.permissions) ? draft.permissions : (active?.[3] || []);
    const tierSelect = `<label class="is-wide dwrt-kit-field" data-dwrt-component="field"><span>权限档<small>限制整个组内用户的操作范围；成员的实际权限取组档与其自身角色的交集。</small></span>
      <select data-system-group-draft="permissionTier">${choices.map(([value, label]) => `<option value="${escapeHtml(value)}" ${current === value ? 'selected' : ''}>${escapeHtml(label)}</option>`).join('')}</select></label>`;
    const hint = active?.[2] ? `<div class="system-user-policy-note">${escapeHtml(active[2])}</div>` : '';
    const custom = isCustom
      ? `<fieldset class="system-user-permission-set">
          <legend>自定义权限项<small>最多 16 项</small></legend>
          ${SYSTEM_USER_PERMISSION_CHOICES.map(([value, label]) => `<label class="system-user-permission-choice"><input type="checkbox" data-system-group-permission-toggle="${escapeHtml(value)}" ${selected.includes(value) ? 'checked' : ''}><span>${escapeHtml(label)}<small>${escapeHtml(value)}</small></span></label>`).join('')}
        </fieldset>`
      : `<div class="system-user-policy-note">该档包含：${escapeHtml((active?.[3] || []).map((permission) => permissionLabel(permission)).join('、') || '无')}</div>`;
    return `${tierSelect}${hint}${custom}`;
  }

  function permissionLabel(value) {
    const found = SYSTEM_USER_PERMISSION_CHOICES.find(([permission]) => permission === value);
    return found ? found[1] : value;
  }

  function groupTierGapText(cap) {
    if (cap === false) return '后端当前未开放组级权限档，因此这里不提供档位选择。已提交交接单请求该能力。';
    return '组级权限档尚无后端存储与能力声明（web_user_groups 只有名称与备注两列，组写入也不接受权限字段），所以这里不放一个存不进去的档位选择。已提交交接单请求该合同。';
  }

  /*
   * 表格里的档位单元格。三种情况分开说：后端给了档位就显示档名；
   * 能力位为真但这个组还没设置就说「未设置」；能力位未确认时说「未接入」，
   * 不用一个横杠把三件事混成一个样子。
   */
  function groupTierCellText(group) {
    if (group.permissionTier) return groupTierLabel(group.permissionTier);
    if (state.capabilities.groupPermissionTier === true) return '未设置';
    return '未接入';
  }

  function importDrawer() {
    const body = `<div class="system-users-import-summary"><strong>${escapeHtml(state.importName || '未选择文件')}</strong><span>${state.importRows.length} 位用户 · ${state.importErrors.length ? `${state.importErrors.length} 个错误` : '校验通过'}</span></div>${state.importErrors.length ? `<div class="system-users-notice">${state.importErrors.map(escapeHtml).join('<br>')}</div>` : ''}<div class="system-users-import-list">${state.importRows.slice(0, 40).map((row) => `<div><strong>${escapeHtml(row.username)}</strong><span>${escapeHtml([row.email, row.role].filter(Boolean).join(' · '))}</span></div>`).join('')}</div>`;
    const footer = `<button class="policy-secondary" type="button" data-system-user-close>取消</button><button class="policy-primary" type="button" data-system-user-import-save ${state.capabilities.import && state.importRows.length && !state.importErrors.length && !state.saving ? '' : 'disabled'}>${state.saving ? '正在导入' : '确认导入'}</button>`;
    return drawerShell('CSV IMPORT', '导入用户', body, footer, '导入用户');
  }

  function renderDrawer() {
    if (state.drawer === 'detail' && state.selected) return detailDrawer(state.selected);
    if (state.drawer === 'create') return createDrawer();
    if (state.drawer === 'api-key-create') return apiKeyCreateDrawer();
    if (state.drawer === 'groups') return groupsDrawer();
    if (state.drawer === 'import') return importDrawer();
    return '';
  }

  function render() {
    if (!root || !state.mounted) return;
    root.hidden = false;
    root.classList.remove('route-line-status', 'route-data-page', 'route-client-details-host', 'route-insights-host', 'route-insights-home', 'route-log-center-host');
    root.classList.add('route-workspace', 'policy-table-route-host', MODULE_CLASS);
    root.innerHTML = `<section class="policy-table-shell system-users-shell">${pageTabsMarkup()}<div class="system-users-page-panel" data-system-users-page-panel>${pageTabPanelMarkup()}</div>${renderDrawer()}</section>`;
    bindEvents();
    ui.mountAll?.(root);
    /* mountAll 把抽屉搬进 portal 后再同步一次壁纸，否则搬移后那层是空的。 */
    syncDrawerWallpaper();
    /* 抽屉刚重建，Tab 条是新节点：把运行时探测结果重新贴上去。 */
    syncActivityTab();
    ui.scheduleGlassCardsRender?.(120);
  }

  /*
   * 切换页面级 Tab 只换面板内容，理由与 patchDetailTab() 相同：
   * 整页 render() 会把抽屉连同 portal 宿主一起重建。这里还要额外注意
   * 一件事——切 Tab 时抽屉可能正开着（例如从详情抽屉里点了页面 Tab），
   * 面板换掉不影响抽屉，正是我们要的。
   */
  function patchPageTabPanel() {
    if (!state.mounted || !root) return false;
    const panel = root.querySelector('[data-system-users-page-panel]');
    if (!panel) return false;
    panel.innerHTML = pageTabPanelMarkup();
    root.querySelectorAll('[data-system-users-page-tab]').forEach((tab) => {
      const active = tab.dataset.systemUsersPageTab === state.pageTab;
      tab.classList.toggle('is-active', active);
      tab.setAttribute('aria-selected', active ? 'true' : 'false');
    });
    /* 面板里的控件都是新节点：重新绑定，并让 kit 重新挂载其中的组件。 */
    bindPagePanelControls();
    ui.mountAll?.(panel);
    ui.scheduleGlassCardsRender?.(120);
    return true;
  }

  /*
   * 面板内控件的绑定。整页 render() 与 patchPageTabPanel() 共用，
   * 因为面板换过之后这些节点全是新的（design.md 规则 15(b)）。
   */
  function bindPagePanelControls() {
    root.querySelector('[data-system-user-search]')?.addEventListener('input', (event) => { state.query = event.target.value || ''; patchTable(); });
    root.querySelector('[data-system-user-permission]')?.addEventListener('change', (event) => { state.permission = event.target.value || 'all'; patchTable(); });
    root.querySelector('[data-system-user-create-menu]')?.addEventListener('click', () => { state.createMenu = !state.createMenu; const menu = root.querySelector('.system-users-create-menu'); if (menu) menu.hidden = !state.createMenu; });
    root.querySelector('[data-system-user-create]')?.addEventListener('click', () => { state.createMenu = false; state.drawer = 'create'; state.draft = { role: 'admin' }; state.notice = ''; render(); });
    root.querySelector('[data-system-user-groups]')?.addEventListener('click', () => { state.drawer = 'groups'; render(); });
    root.querySelector('[data-system-user-import]')?.addEventListener('click', () => root.querySelector('[data-system-user-import-file]')?.click());
    root.querySelector('[data-system-user-import-file]')?.addEventListener('change', handleImportFile);
    /* 「组」视图里的创建按钮沿用抽屉那套草稿流程，不另造一份表单。 */
    root.querySelector('[data-system-group-page-new]')?.addEventListener('click', () => {
      state.drawer = 'groups';
      state.groupDraftOpen = true;
      state.groupDraft = { name: '', description: '' };
      state.notice = '';
      render();
    });
    root.querySelectorAll('[data-system-group-delete]').forEach((button) => button.addEventListener('click', () => deleteGroup(button.dataset.systemGroupDelete)));
    root.querySelector('[data-system-api-keys-refresh]')?.addEventListener('click', () => loadApiKeys());
    root.querySelector('[data-system-api-key-create]')?.addEventListener('click', () => {
      if (state.apiKeys.capabilities.create !== true || state.saving) return;
      state.drawer = 'api-key-create';
      state.apiKeys.draft = apiKeyDraftDefaults();
      state.apiKeys.created = null;
      state.apiKeys.notice = '';
      render();
    });
    bindDetailActions();
    bindAvatarImages();
  }

  function patchTable() {
    const tbody = root.querySelector('.system-users-table tbody');
    const count = root.querySelector('.system-users-table-meta .dwrt-kit-table-count');
    const users = filteredUsers();
    if (tbody) tbody.innerHTML = users.length ? users.map(userRow).join('') : '<tr><td colspan="7" class="dwrt-kit-table-empty">没有匹配的用户</td></tr>';
    if (count) count.textContent = `${users.length} / ${state.users.length} 位用户`;
    bindDetailActions();
    bindAvatarImages(tbody);
  }

  function patchLoadedUsers() {
    const card = root.querySelector('.system-users-table-card');
    if (!card) return render();
    const scroll = card.querySelector('.system-users-table-scroll');
    const scrollTop = scroll?.scrollTop || 0;
    const scrollLeft = scroll?.scrollLeft || 0;
    card.outerHTML = renderTable();
    const nextScroll = root.querySelector('.system-users-table-scroll');
    if (nextScroll) {
      nextScroll.scrollTop = scrollTop;
      nextScroll.scrollLeft = scrollLeft;
    }
    const permission = root.querySelector('[data-system-user-permission]');
    if (permission) {
      permission.innerHTML = `<option value="all">全部权限</option>${permissionOptions().map((item) => `<option value="${escapeHtml(item)}" ${state.permission === item ? 'selected' : ''}>${escapeHtml(item)}</option>`).join('')}`;
    }
    root.querySelector('[data-system-user-create]')?.toggleAttribute('disabled', !state.capabilities.create);
    root.querySelector('[data-system-user-import]')?.toggleAttribute('disabled', !state.capabilities.import);
    bindDetailActions();
    bindAvatarImages(root.querySelector('.system-users-table-card'));
  }

  /*
   * 只换活动面板的内容，不整体 render()：整体重绘会重建 `.dwrt-kit-sheet`，
   * kit 重播入场动画并把正文滚动位置清零，切一次档位就闪一下。
   * 查节点从 drawerScope() 出发——抽屉已被 ui.mountAll() 搬进 portal，
   * root.querySelector 取不到（同一处坑见 syncSettingsFooter 的注释）。
   */
  function patchActivityPanel() {
    if (!state.mounted || state.detailTab !== 'activity') return;
    const panel = drawerScope().querySelector('[data-system-user-activity-panel]');
    if (!panel) return;
    panel.innerHTML = activityPanelInnerMarkup();
  }

  /*
   * 切换详情 Tab 只换正文，不整体 render()。
   *
   * 原先这里调 render()，而 render() 是 `root.innerHTML = ...` 整页重写：
   * `.dwrt-kit-sheet` 连同它的 portal 宿主一起被销毁重建，kit 重播入场动画、
   * 正文滚动位置清零、头像重新拉一遍——用户 2026-08-05 的原话是
   * 「点击用户后进入的抽屉，点一下它就重新加载一下」。实测标记法证实过：
   * 切 tab 前给 `.system-users-drawer` 挂上 `dataset` 与 JS 属性，切完两者都没了。
   *
   * 这里只做三件事：换正文、更新 Tab 条的选中态、重挂 kit 控件。
   * 查节点一律从 drawerScope() 出发，因为抽屉已被 ui.mountAll() 搬进 portal，
   * root.querySelector 取不到（同 patchActivityPanel / syncSettingsFooter）。
   */
  function patchDetailTab() {
    const user = state.selected;
    if (!state.mounted || !user || state.drawer !== 'detail') return false;
    const scope = drawerScope();
    const panel = scope.querySelector('[data-system-user-detail-panel]');
    if (!panel) return false;

    /* 设置页的草稿必须在渲染正文之前播种，理由同 detailDrawer()。 */
    if (state.detailTab === 'settings') settingsDraftFor(user);
    panel.innerHTML = detailTabBodyMarkup(user, credentialsFor(user));

    scope.querySelectorAll('[data-system-user-tab]').forEach((tab) => {
      const active = tab.dataset.systemUserTab === state.detailTab;
      tab.classList.toggle('is-active', active);
      tab.setAttribute('aria-selected', active ? 'true' : 'false');
    });

    /* 页脚按钮只在设置页出现，正文换了要跟着换。 */
    let footer = scope.querySelector('.dwrt-kit-sheet-footer');
    const footerMarkup = detailFooterMarkup(user);
    if (!footer && footerMarkup) {
      footer = document.createElement('footer');
      footer.className = 'dwrt-kit-sheet-footer';
      scope.querySelector('.system-users-drawer-content')?.appendChild(footer);
    }
    if (footer && footerMarkup) footer.innerHTML = footerMarkup;
    else if (footer && !footerMarkup) footer.innerHTML = '';

    /* 新正文里的按钮和 kit 控件都是新节点，要重新绑定与挂载。 */
    bindDrawerControls(scope);
    ui.mountAll?.(scope);
    syncActivityTab();
    if (state.detailTab === 'settings') syncSettingsFooter();
    return true;
  }

  /*
   * 探测结果回来后同步 Tab 条自身的可用性。少了这一步，`detailTabsMarkup()` 里那支
   * 「未实现就禁用」的分支永远等不到重绘——抽屉是在探测之前渲染的——于是判据写了
   * 却不生效，等于换了个地方写死。这里只改这一颗按钮的属性，不重绘抽屉。
   */
  function syncActivityTab() {
    if (!state.mounted) return;
    const tab = drawerScope().querySelector('[data-system-user-tab="activity"]');
    if (!tab) return;
    const unimplemented = state.activity.probe === 'unimplemented';
    tab.disabled = unimplemented;
    if (unimplemented && state.activity.error) tab.dataset.dwrtTooltip = state.activity.error;
    else delete tab.dataset.dwrtTooltip;
  }

  /*
   * 换用户就重置活动状态并重新探测。档位候选跟着还原：上一个用户身上被 400
   * 剔掉的档，对这个用户未必也不接受（invalid_range 是全局的，但探测本来就便宜，
   * 与其推断不如再问一次后端）。
   */
  function resetActivityFor(username) {
    state.activity = {
      username,
      probe: 'idle',
      error: '',
      range: '',
      type: 'all',
      ranges: [...SYSTEM_USER_ACTIVITY_RANGE_CANDIDATES],
      data: null,
      seq: state.activity.seq
    };
    loadActivity(username, { range: '', type: 'all' });
  }

  function closeDrawer() {
    state.drawer = '';
    state.selected = null;
    state.notice = '';
    state.detailTab = 'overview';
    state.settingsDraft = null;
    state.settingsError = '';
    /*
     * 明文随抽屉一起丢掉。留在 state 里意味着下次打开抽屉还能看到一把
     * 「只显示一次」的密钥，那句话就不成立了。
     */
    state.apiKeys.draft = null;
    state.apiKeys.created = null;
    state.apiKeys.notice = '';
    render();
  }

  function bindDetailActions() {
    const openDetail = (id) => {
      state.selected = state.users.find((user) => user.id === id) || null;
      if (!state.selected) return;
      state.drawer = 'detail';
      state.notice = '';
      state.detailTab = 'overview';
      state.settingsDraft = null;
      state.settingsError = '';
      render();
      /*
       * 进抽屉就探一次活动端点，Tab 的可用性等这次探测的结果，
       * 不靠任何写死的开关。探测本身是一次真实的默认档读取，
       * 所以点进 Tab 时数据已经在手，不必再等一轮。
       */
      resetActivityFor(state.selected.username);
    };
    root.querySelectorAll('[data-system-user-detail]').forEach((button) => button.addEventListener('click', (event) => {
      event.stopPropagation();
      openDetail(button.dataset.systemUserDetail);
    }));
    /*
     * 用户要求「点击对应用户后」开抽屉，所以整行都要可点。
     * 行内已有按钮（名字那颗、以及后续可能的操作按钮）自己处理点击，
     * 这里遇到 button/a 就让位，避免双触发。
     */
    root.querySelectorAll('tr[data-system-user-id]').forEach((row) => {
      row.addEventListener('click', (event) => {
        if (event.target.closest('button, a, input, select, label')) return;
        openDetail(row.dataset.systemUserId);
      });
      row.addEventListener('keydown', (event) => {
        if (event.key !== 'Enter' && event.key !== ' ') return;
        if (event.target !== row) return;
        event.preventDefault();
        openDetail(row.dataset.systemUserId);
      });
    });
  }

  /*
   * 抽屉壁纸同步，实现照 ai-assistant.js:278 `syncDrawerWallpaper()`。
   * 抽屉自身透明，材质由 `.system-users-drawer-material` 的 backdrop-filter 负责，
   * 底下这层壁纸必须按视口尺寸铺满并跟随主题的 objectFit/filter/opacity，
   * 否则抽屉里会出现和页面壁纸错位的一块。
   */
  function syncDrawerWallpaper() {
    const wallpaper = document.getElementById('appWallpaper');
    /* 抽屉被 ui.mountAll() 搬到 body 下的 portal，只能从 document 查。 */
    const image = document.querySelector('.system-users-drawer [data-system-users-drawer-wallpaper]');
    if (!wallpaper || !image) return;
    const src = wallpaper.currentSrc || wallpaper.getAttribute('src') || '';
    if (src && image.getAttribute('src') !== src) image.setAttribute('src', src);
    const style = getComputedStyle(wallpaper);
    image.style.objectFit = style.objectFit || 'cover';
    image.style.objectPosition = style.objectPosition || '50% 50%';
    image.style.filter = style.filter || 'none';
    image.style.opacity = style.opacity || '1';
  }

  function onWallpaperChange() {
    requestAnimationFrame(syncDrawerWallpaper);
  }

  function bindAvatarImages(scope = root) {
    scope?.querySelectorAll?.('[data-system-user-avatar-image]').forEach((image) => {
      image.addEventListener('error', () => {
        image.hidden = true;
        image.closest('.system-user-avatar')?.classList.remove('has-image');
      }, { once: true });
    });
  }

  function patchUserAvatars(username) {
    const user = state.users.find((item) => item.username.toLowerCase() === String(username || '').toLowerCase());
    if (!user) return;
    root.querySelectorAll('[data-system-user-avatar-for]').forEach((avatar) => {
      if (String(avatar.dataset.systemUserAvatarFor || '').toLowerCase() !== user.username.toLowerCase()) return;
      const large = avatar.dataset.systemUserAvatarSize === 'large';
      avatar.outerHTML = avatarMarkup(user, large);
    });
    bindAvatarImages();
  }

  function onAdminAvatarChanged(event) {
    if (!state.mounted) return;
    const username = firstText(event?.detail?.username, state.currentUsername, localStorage.getItem('dreamingwrt.web.username'));
    const avatarUrl = normalizeSystemUserAvatarUrl(event?.detail?.avatar_url || event?.detail?.avatarUrl);
    if (!username || !avatarUrl) return;
    state.avatarRevision = Date.now();
    state.users = mergeSystemUserAvatar(state.users, { username, avatar_url: avatarUrl });
    if (state.selected?.username?.toLowerCase() === username.toLowerCase()) {
      state.selected = state.users.find((item) => item.id === state.selected.id) || state.selected;
    }
    patchUserAvatars(username);
  }

  function bindEvents() {
    /*
     * 面板内的控件（搜索、筛选、新建、组视图、API 视图）绑在这里之外，
     * 因为切页面 Tab 只换面板、那些节点会被替换，两条路径必须共用同一份绑定。
     */
    bindPagePanelControls();

    /* 页面级 Tab 切换：只换面板，拿不到面板才退回整页渲染。 */
    root.querySelectorAll('[data-system-users-page-tab]').forEach((tab) => tab.addEventListener('click', () => {
      const next = tab.dataset.systemUsersPageTab;
      if (!next || next === state.pageTab) return;
      state.pageTab = next;
      state.createMenu = false;
      /*
       * 抽屉开着时点不到这里：kit 的遮罩是 `position: fixed` 全屏、z-index 68，
       * 会盖住 Tab 条（实测 elementFromPoint 命中 .dwrt-kit-sheet-overlay），
       * 用户必须先关抽屉。这是模态抽屉应有的行为，不需要在这里额外兜底。
       */
      if (!patchPageTabPanel()) render();
      /*
       * API 密钥按需拉取：只有真的切到这个 Tab 才请求。
       * 失败在网络 / 5xx / 权限上时允许再试一次（用户可能刚换了账号），
       * 但「未实现」不重试——那不是暂时状态。
       */
      if (next === 'api' && ['idle', 'network', 'server', 'unavailable', 'error', 'forbidden', 'unauthorized'].includes(state.apiKeys.probe)) {
        loadApiKeys();
      }
    }));
    root.querySelectorAll('[data-system-user-close]').forEach((button) => button.addEventListener('click', closeDrawer));
    root.querySelector('[data-system-user-save]')?.addEventListener('click', saveUser);
    root.querySelector('[data-system-api-key-save]')?.addEventListener('click', saveApiKey);
    root.querySelector('[data-system-api-key-copy]')?.addEventListener('click', copyApiKeyPlaintext);
    /*
     * Tab 切换与设置保存在这里绑，是因为 bindEvents() 跑在 ui.mountAll() **之前**，
     * 此时抽屉还是 root 的后代，能查到；节点之后被搬进 portal 也不会丢监听器
     * （移动 DOM 节点不清除已绑的 listener），既有的 close/save 按钮就是这么工作的。
     */
    bindDrawerControls(root);
    root.querySelector('[data-system-user-import-save]')?.addEventListener('click', importUsers);
    root.querySelector('[data-system-group-new]')?.addEventListener('click', () => { state.groupDraftOpen = true; state.groupDraft = { name: '', description: '' }; state.notice = ''; render(); });
    root.querySelector('[data-system-group-cancel]')?.addEventListener('click', () => { state.groupDraftOpen = false; state.groupDraft = {}; state.notice = ''; render(); });
    root.querySelector('[data-system-group-save]')?.addEventListener('click', saveGroup);
    syncDrawerWallpaper();
  }

  /*
   * 抽屉内控件的绑定。两条路径共用：整页 render() 之后，以及 patchDetailTab()
   * 只换正文之后。切 Tab 不再整体重绘，所以这些监听器必须能被单独重挂——
   * 留在 bindEvents() 里只绑一次的话，换过正文的设置页按钮就是死的
   * （design.md 规则 15(b) 记的就是这件事）。
   *
   * scope 参数让调用方决定作用域：render() 时抽屉还在 root 里，
   * patchDetailTab() 时它已被搬进 portal，只能从 drawerScope() 查。
   */
  function bindDrawerControls(scope) {
    scope.querySelectorAll('[data-system-user-tab]').forEach((tab) => tab.addEventListener('click', () => {
      const next = tab.dataset.systemUserTab;
      if (!next || next === state.detailTab || tab.disabled) return;
      state.detailTab = next;
      state.settingsError = '';
      /* 只换正文；拿不到面板（例如抽屉刚被别的路径重绘）才退回整页渲染。 */
      if (!patchDetailTab()) render();
      /*
       * 若探测那一轮失败在网络/5xx 上（不是「未实现」），点进 Tab 时重试一次：
       * 这类失败是暂时的，不该把用户困在一句错误里没有出路。
       */
      if (next === 'activity' && ['network', 'server', 'unavailable', 'error'].includes(state.activity.probe)) {
        loadActivity(state.activity.username || state.selected?.username || '', { range: state.activity.range, type: state.activity.type });
      }
    }));
    scope.querySelector('[data-system-user-settings-save]')?.addEventListener('click', saveUserSettings);
    scope.querySelector('[data-system-user-settings-reset]')?.addEventListener('click', () => {
      state.settingsDraft = null;
      state.settingsError = '';
      if (!patchDetailTab()) render();
    });
  }

  /*
   * 表单输入走 document 上的事件委托，只在 mount 时绑一次。
   *
   * 起因是「输入组名后『创建组』按钮的 disabled 始终不摘」。真因不是事件收不到：
   * `ui.mountAll()` 把 `.dwrt-kit-sheet` 搬到 `body > .dwrt-kit-sheet-portal` 后，
   * ui-kit 自己会把 click/input/change/submit/keydown 重放回原宿主链
   * （dwrt-ui-kit.js 的 `DELEGATED_EVENTS` / `bindSheetDelegation()`），
   * 30.1 实测重放确实到达了 routePreview。
   *
   * 真正断掉的是**回写那一步**：抽屉已经不是 root 的后代，
   * `root.querySelector('[data-system-group-save]')` 实测返回 null
   * （同一时刻 `document.querySelector(...)` 能取到），于是拿不到按钮、
   * disabled 永远不被摘掉。所以这里两件事都要做：委托绑在 document 上，
   * 且查节点必须从抽屉自身的作用域（`drawerScope()`）出发，不能用 root。
   */
  function bindDelegatedInputs() {
    document.addEventListener('input', onDelegatedInput);
    document.addEventListener('change', onDelegatedChange);
    /*
     * 档位与类型按钮必须走委托：patchActivityPanel() 用 innerHTML 换掉面板内容，
     * 直接绑在按钮上的监听器会随旧节点一起消失，切一次档之后就再也切不动。
     * 绑在 document 上，节点换多少次都不影响。
     */
    document.addEventListener('click', onDelegatedActivityClick);
  }

  function drawerScope() {
    return document.querySelector('.system-users-drawer') || root;
  }

  function onDelegatedActivityClick(event) {
    if (!state.mounted) return;
    const target = event.target;
    if (!target?.closest?.('.system-users-drawer')) return;
    const rangeButton = target.closest('[data-system-user-activity-range]');
    const typeButton = target.closest('[data-system-user-activity-type]');
    if (!rangeButton && !typeButton) return;
    if (state.activity.probe === 'loading') return;
    const username = state.activity.username || state.selected?.username || '';
    if (!username) return;
    if (rangeButton) {
      const range = rangeButton.dataset.systemUserActivityRange;
      if (!range || range === state.activity.range) return;
      loadActivity(username, { range, type: state.activity.type });
      return;
    }
    const type = typeButton.dataset.systemUserActivityType;
    if (!type || type === state.activity.type) return;
    loadActivity(username, { range: state.activity.range, type });
  }

  function onDelegatedInput(event) {
    if (!state.mounted) return;
      const target = event.target;
      if (!target?.dataset) return;
    if (!target.closest('.system-users-drawer')) return;
      if (target.dataset.userDraft) {
        state.draft[target.dataset.userDraft] = target.value || '';
      const save = drawerScope().querySelector('[data-system-user-save]');
        if (save) save.disabled = !(state.capabilities.create && state.draft.username && state.draft.password) || state.saving;
        return;
      }
      if (target.dataset.systemGroupDraft) {
        state.groupDraft[target.dataset.systemGroupDraft] = target.value || '';
      const save = drawerScope().querySelector('[data-system-group-save]');
        if (save) save.disabled = !String(state.groupDraft.name || '').trim() || state.saving;
        return;
      }
    /*
     * 密钥草稿：只更新 state 与保存按钮的可用性，不整体重绘，
     * 否则输入一个字符就会丢焦点（design.md 系统设置页规则 6）。
     */
    if (target.dataset.apiKeyDraft) {
      apiKeyDraft()[target.dataset.apiKeyDraft] = target.value || '';
      const save = drawerScope().querySelector('[data-system-api-key-save]');
      if (save) save.disabled = !String(apiKeyDraft().name || '').trim() || state.saving;
      return;
    }
    if (target.dataset.systemUserSetting) {
      applySettingInput(target);
    }
  }

  function onDelegatedChange(event) {
    if (!state.mounted) return;
      const target = event.target;
    if (!target?.closest?.('.system-users-drawer')) return;
      if (target?.dataset?.userDraft === 'role') state.draft.role = target.value || 'admin';
    /*
     * 档位与有效期是 select，改动要重绘：档位说明与「永不过期」的更换提示
     * 都跟着当前选择变，只改 state 的话说明文字会与选中项脱节。
     */
    if (target?.dataset?.apiKeyDraft === 'tier' || target?.dataset?.apiKeyDraft === 'expires') {
      apiKeyDraft()[target.dataset.apiKeyDraft] = target.value || '';
      render();
      return;
    }
    if (target?.dataset?.systemUserSetting) {
      applySettingInput(target);
      return;
    }
    /*
     * 组权限档是 select，改动要重绘：档位说明与「自定义」档的勾选清单都跟着
     * 当前选择变，只改 state 的话说明文字会与选中项脱节（同 apiKeyDraft 的 tier）。
     */
    if (target?.dataset?.systemGroupDraft === 'permissionTier') {
      state.groupDraft = { ...(state.groupDraft || {}), permissionTier: target.value || '' };
      const tier = groupTierChoices().find(([value]) => value === state.groupDraft.permissionTier);
      /* 切到预设档时用该档的组合覆盖草稿；切到自定义档保留已勾选项。 */
      if (tier && Array.isArray(tier[3])) state.groupDraft.permissions = [...tier[3]];
      render();
      return;
    }
    /* 自定义档的逐项勾选。上限 16 项与用户权限同源，避免提交必然 400 的 body。 */
    if (target?.dataset?.systemGroupPermissionToggle) {
      const value = target.dataset.systemGroupPermissionToggle;
      const next = new Set(Array.isArray(state.groupDraft?.permissions) ? state.groupDraft.permissions : []);
      if (target.checked) next.add(value); else next.delete(value);
      state.groupDraft = {
        ...(state.groupDraft || {}),
        permissions: SYSTEM_USER_PERMISSION_CHOICES
          .map(([permission]) => permission)
          .filter((permission) => next.has(permission))
          .slice(0, 16)
      };
      if (!state.groupDraft.permissions.includes(value) && target.checked) target.checked = false;
      return;
    }
    /* 安全策略段的布尔开关：与权限勾选分开，因为它写的是单个字段而不是数组。 */
    if (target?.dataset?.systemUserSettingToggle) {
      const draft = state.settingsDraft;
      if (!draft) return;
      draft[target.dataset.systemUserSettingToggle] = Boolean(target.checked);
      syncSettingsFooter();
      return;
    }
    if (target?.dataset?.systemUserPermissionToggle) {
      const draft = state.settingsDraft;
      if (!draft) return;
      const value = target.dataset.systemUserPermissionToggle;
      const next = new Set(draft.permissions);
      if (target.checked) next.add(value); else next.delete(value);
      /*
       * 后端 webd_directory_permissions_ok() 的数组上限是 16 项，白名单本身只有 11 项，
       * 所以正常勾不满；这里仍然按上限截断，避免将来白名单扩容后前端提交一个
       * 必然 400 的 body。
       */
      draft.permissions = SYSTEM_USER_PERMISSION_CHOICES
        .map(([permission]) => permission)
        .filter((permission) => next.has(permission))
        .slice(0, 16);
      if (!draft.permissions.includes(value) && target.checked) target.checked = false;
      syncSettingsFooter();
    }
  }

  function applySettingInput(target) {
    const draft = state.settingsDraft;
    if (!draft) return;
    const field = target.dataset.systemUserSetting;
    /* 周期是天数，存成数字：存字符串会让脏判定与 body 里的类型都跟着漂。 */
    if (field === 'passwordRotateDays') draft[field] = Number(target.value || 0) || 0;
    else draft[field] = target.value || '';
    syncSettingsFooter();
  }

  /*
   * 只回写页脚两颗按钮的 disabled，不整体 render()。
   * 整体重绘会让输入框失去焦点、光标跳到末尾，中文输入法下还会吞掉未上屏的拼音。
   * 查节点必须从 drawerScope() 出发：抽屉已被搬进 portal，root.querySelector 取不到。
   */
  function syncSettingsFooter() {
    const user = state.selected;
    if (!user || state.detailTab !== 'settings') return;
    const dirty = settingsDirtyFields(user).length > 0;
    const scope = drawerScope();
    const save = scope.querySelector('[data-system-user-settings-save]');
    const reset = scope.querySelector('[data-system-user-settings-reset]');
    if (save) save.disabled = !(state.capabilities.update === true && dirty) || state.saving;
    if (reset) reset.disabled = !dirty || state.saving;
    const flag = scope.querySelector('.system-user-settings-dirty');
    if (flag) flag.hidden = !dirty;
  }

  function parseCsv(text) {
    const rows = [];
    let row = [];
    let value = '';
    let quoted = false;
    const source = String(text || '').replace(/^\uFEFF/, '');
    for (let index = 0; index < source.length; index += 1) {
      const char = source[index];
      if (char === '"') {
        if (quoted && source[index + 1] === '"') { value += '"'; index += 1; } else quoted = !quoted;
      } else if (char === ',' && !quoted) { row.push(value); value = ''; }
      else if ((char === '\n' || char === '\r') && !quoted) { if (char === '\r' && source[index + 1] === '\n') index += 1; row.push(value); value = ''; if (row.some(Boolean)) rows.push(row); row = []; }
      else value += char;
    }
    row.push(value);
    if (row.some(Boolean)) rows.push(row);
    if (!rows.length) return [];
    const headers = rows.shift().map((item) => item.trim().toLowerCase());
    const at = (record, names) => { const index = headers.findIndex((header) => names.includes(header)); return index >= 0 ? firstText(record[index]) : ''; };
    return rows.map((record) => ({ username: at(record, ['username', 'user', '用户名']), display_name: at(record, ['display_name', 'name', '显示名称', '姓名']), email: at(record, ['email', '邮箱']), role: at(record, ['role', '角色']) || 'viewer', password: at(record, ['password', '初始密码']) }));
  }

  async function handleImportFile(event) {
    const file = event.target.files?.[0];
    event.target.value = '';
    if (!file) return;
    const rows = parseCsv(await file.text());
    const seen = new Set();
    const errors = [];
    rows.forEach((row, index) => {
      if (!row.username) errors.push(`第 ${index + 2} 行缺少用户名`);
      if (row.username && seen.has(row.username.toLowerCase())) errors.push(`用户名重复：${row.username}`);
      if (row.username) seen.add(row.username.toLowerCase());
    });
    if (!rows.length) errors.push('CSV 中没有可导入的用户');
    state.importRows = rows;
    state.importName = file.name;
    state.importErrors = errors.slice(0, 20);
    state.drawer = 'import';
    render();
  }

  async function saveUser() {
    if (!state.capabilities.create || state.saving) return;
    if (state.draft.role === 'owner' && !window.confirm(`将新账号“${state.draft.username}”设为设备所有者？该账号将获得固件升级等高风险操作权限。`)) return;
    state.saving = true;
    state.notice = '';
    render();
    try {
      await requestJson(USERS_ENDPOINT, { method: 'POST', body: JSON.stringify(state.draft) });
      state.drawer = '';
      state.saving = false;
      await load();
      window.DreamingWrtNotify?.success('用户已创建');
    } catch (error) {
      state.saving = false;
      state.notice = `创建失败：${firstText(error.message, 'unknown')}`;
      render();
    }
  }

  /*
   * 创建 API 密钥。body 只放后端会读的四个键，`expires_at` 是绝对秒级时间戳
   * （0 表示永不过期）；后端拒绝过去的时间，所以这里按当下时间加天数换算。
   */
  async function saveApiKey() {
    if (state.apiKeys.capabilities.create !== true || state.saving) return;
    const draft = apiKeyDraft();
    const name = String(draft.name || '').trim();
    if (!name) return;
    const days = Number(draft.expires) || 0;
    const body = {
      name,
      tier: String(draft.tier || 'read_only'),
      expires_at: days > 0 ? Math.floor(Date.now() / 1000) + days * 86400 : 0
    };
    const allowIps = String(draft.allow_ips || '').trim();
    if (allowIps) body.allow_ips = allowIps;
    state.saving = true;
    state.apiKeys.notice = '';
    render();
    try {
      const data = await requestJson(API_KEYS_ENDPOINT, { method: 'POST', body: JSON.stringify(body) });
      state.saving = false;
      state.apiKeys.created = {
        keyId: firstText(data.key_id, data.keyId),
        name: firstText(data.name, name),
        tier: firstText(data.tier, body.tier),
        expiresAt: Math.round(firstNumber(data.expires_at, data.expiresAt, 0)),
        plaintext: firstText(data.api_key, data.apiKey, data.plaintext)
      };
      state.apiKeys.draft = null;
      /*
       * 明文只在响应里出现一次。后端没给（例如未来改成异步下发）时必须说清楚，
       * 不能让用户以为自己漏看了一屏。
       */
      if (!state.apiKeys.created.plaintext) state.apiKeys.notice = '密钥已创建，但后端未在响应中返回明文，请撤销这把并重新创建。';
      render();
      await loadApiKeys();
      window.DreamingWrtNotify?.success('API 密钥已创建');
    } catch (error) {
      state.saving = false;
      state.apiKeys.notice = apiKeyCreateErrorMessage(error);
      render();
    }
  }

  /* 逐条对应 webd_api_keys_create_response() 里的 webd_error() 分支。 */
  function apiKeyCreateErrorMessage(error) {
    const message = firstText(error?.message, error?.payload?.error?.code, 'unknown');
    if (/invalid_name/.test(message)) return '名称不合法：只能包含字母、数字、空格和 - _ .，且不能为空。';
    if (/invalid_tier/.test(message)) return '权限档不被后端接受，请重新选择。';
    if (/expires_at_in_past/.test(message)) return '有效期已经过去，请重新选择一个未来的时间。';
    if (/invalid_allow_ips|allow_ips/.test(message)) return '来源 IP 限制不合法：请填逗号分隔的地址或 CIDR。';
    if (/invalid_scope|scope/.test(message)) return '作用域文档不被后端接受。';
    if (/api_key_create_failed/.test(message)) return '后端写入密钥失败，请稍后重试。';
    if (/self_management_forbidden/.test(message)) return 'API 密钥通道不能自己创建密钥，请用登录会话操作。';
    if (/forbidden/.test(message)) return `当前账号无权创建 API 密钥${state.apiKeys.capabilities.writeMinRole ? `，需要 ${state.apiKeys.capabilities.writeMinRole} 角色` : ''}。`;
    return `创建失败：${message}`;
  }

  async function copyApiKeyPlaintext() {
    const plaintext = state.apiKeys.created?.plaintext || '';
    if (!plaintext) return;
    try {
      /* 非安全上下文下 clipboard API 不存在，退回选中节点让用户自己复制。 */
      if (navigator.clipboard?.writeText) {
        await navigator.clipboard.writeText(plaintext);
        window.DreamingWrtNotify?.success('密钥已复制到剪贴板');
        return;
      }
      throw new Error('clipboard unavailable');
    } catch (_) {
      state.apiKeys.notice = '当前环境不允许自动复制，密钥已选中，请手动复制。';
      render();
      /*
       * 选中必须在 render() **之后**做：render() 重建整个抽屉 DOM，
       * 先选中的那个节点随即被丢掉，选区也跟着失效。
       */
      const node = drawerScope().querySelector('[data-system-api-key-plaintext]');
      if (node && window.getSelection) {
        const range = document.createRange();
        range.selectNodeContents(node);
        const selection = window.getSelection();
        selection.removeAllRanges();
        selection.addRange(range);
      }
    }
  }

  function settingsErrorMessage(error) {
    const message = firstText(error?.message, 'unknown');
    /* 后端错误码逐个对应 webd_directory_user_update() 里的 webd_error() 分支。 */
    if (/invalid_user_update/.test(message)) return '字段校验失败：显示名称需 ≤128 字符、邮箱格式要合法、密码 8~256 位。';
    if (/username_rename_not_supported/.test(message)) return '该接口不支持改用户名。';
    if (/owner_management_forbidden/.test(message)) return '只有设备所有者才能修改所有者账号。';
    if (/owner_role_forbidden/.test(message)) return '只有设备所有者才能授予所有权。旧设备没有所有者时，需由设备持有人确认恢复。';
    if (/self_disable_forbidden/.test(message)) return '不能停用当前登录的账号。';
    if (/last_owner_protected/.test(message)) return '这是最后一个设备所有者。请先将另一启用账号设为设备所有者，再降级、停用或删除原账号。';
    if (/last_manager_protected/.test(message)) return '这是最后一个可用的管理账号，不能停用或降级。';
    if (/user_not_found/.test(message)) return '用户已不存在，请刷新后重试。';
    if (/forbidden/.test(message)) return '当前账号没有修改用户的权限。';
    return `保存失败：${message}`;
  }

  /*
   * 保存「设置」Tab。
   *
   * 契约取自 jmx_app_api.c:60029 的路由与 :49502 `webd_directory_user_update()`：
   *   PATCH /api/v1/system/users/<username>
   * 注意路径参数是**用户名**，不是 id —— 后端 webd_directory_user_json() 把 id 也填成
   * username（:48977），两者当前同值，但仍按契约用 username，避免将来 id 变成真 UUID 时静默打错人。
   * body 只带真的改了的字段（后端 UPDATE 用 COALESCE，缺键即保持原值）。
   *
   * 保存后**重新拉取并回读校验**，不做乐观更新：这是交接单验收标准第 1 条，
   * 也是 design.md 规则 9 的要求（不得假保存）。回读不一致就报出来，不谎报成功。
   */
  async function saveUserSettings() {
    const user = state.selected;
    if (!user || state.saving || state.capabilities.update !== true) return;
    const draft = settingsDraftFor(user);
    const dirty = settingsDirtyFields(user);
    if (!dirty.length) return;
    if (dirty.includes('role') && (draft.role === 'owner' || user.role === 'owner')) {
      const message = draft.role === 'owner'
        ? `将“${user.username}”设为设备所有者？该账号将获得固件升级等高风险操作权限。`
        : `将“${user.username}”从设备所有者改为${roleLabel(draft.role)}？请先确认另一启用账号已接任所有者。`;
      if (!window.confirm(message)) return;
    }
    const body = {};
    if (dirty.includes('display_name')) body.display_name = String(draft.display_name || '');
    if (dirty.includes('email')) body.email = String(draft.email || '');
    if (dirty.includes('role')) body.role = String(draft.role || '');
    if (dirty.includes('status')) body.status = draft.status === 'active' ? 'active' : 'disabled';
    if (dirty.includes('password')) body.password = String(draft.password || '');
    if (dirty.includes('permissions')) body.permissions = [...draft.permissions];
    /* 键名用后端契约里的下划线形式；只有能力位为真时 dirty 里才会出现它们。 */
    if (dirty.includes('api_key_create_denied')) body.api_key_create_denied = draft.apiKeyCreateDenied === true;
    if (dirty.includes('password_rotate_days')) body.password_rotate_days = Number(draft.passwordRotateDays || 0);
    state.saving = true;
    state.settingsError = '';
    render();
    try {
      await requestJson(`${USERS_ENDPOINT}/${encodeURIComponent(user.username)}`, {
        method: 'PATCH',
        body: JSON.stringify(body)
      });
      /*
       * 回读：单用户 GET 是权威值，避免拿列表缓存自证。
       * requestJson() 已经剥过 envelope 的 data 层，这里直接就是用户对象。
       */
      const readback = normalizeUser(await requestJson(`${USERS_ENDPOINT}/${encodeURIComponent(user.username)}`));
      const mismatches = [];
      if (dirty.includes('display_name') && readback.displayName !== body.display_name) mismatches.push('显示名称');
      if (dirty.includes('email') && readback.email !== body.email) mismatches.push('邮箱');
      if (dirty.includes('role') && readback.role !== body.role) mismatches.push('角色');
      if (dirty.includes('status') && (readback.status === 'active' ? 'active' : 'disabled') !== body.status) mismatches.push('状态');
      if (dirty.includes('permissions') && [...readback.permissions].sort().join(',') !== [...body.permissions].sort().join(',')) mismatches.push('权限项');
      /*
       * 这两项的回读尤其重要：它们是新合同，后端可能收下请求却没有落库
       * （COALESCE 的列表里没有这两列时就是这样），回读不一致必须报出来，
       * 否则界面会显示保存成功而实际什么都没改。
       */
      if (dirty.includes('api_key_create_denied')
        && (readback.apiKeyCreateDenied === true) !== body.api_key_create_denied) mismatches.push('禁止创建 API 密钥');
      if (dirty.includes('password_rotate_days')
        && Number(readback.passwordRotateDays || 0) !== body.password_rotate_days) mismatches.push('周期性修改密码');
      state.saving = false;
      state.settingsDraft = null;
      await load();
      state.selected = state.users.find((item) => item.username === user.username) || readback;
      // load() may render the old selection and recreate its draft.
      state.settingsDraft = null;
      if (mismatches.length) {
        state.settingsError = `已提交，但回读校验不一致：${mismatches.join('、')}。请重新确认后端是否接受了这些字段。`;
        render();
        return;
      }
      render();
      window.DreamingWrtNotify?.success('用户设置已保存');
    } catch (error) {
      state.saving = false;
      state.settingsError = settingsErrorMessage(error);
      render();
    }
  }

  /*
   * 创建用户组。契约取自 jmx_app_api.c:49730 `webd_directory_group_write()`：
   * POST /api/v1/system/user-groups  body { name, description, members[] }
   * name 必填、≤128 字符且不含控制字符；description ≤512；
   * members 是用户名数组，带外键，成员不存在返回 409 group_member_not_found；
   * 名称/ID 重复返回 409 user_group_exists。成功时直接回全量组列表。
   */
  async function saveGroup() {
    const name = String(state.groupDraft.name || '').trim();
    if (!name || state.saving) return;
    state.saving = true;
    state.notice = '';
    render();
    try {
      const body = { name, description: String(state.groupDraft.description || '').trim() };
      /*
       * 权限档只在后端声明了该能力时才随请求发出。能力位未确认时多发这两个键，
       * 后端会静默丢弃，界面却会显示创建成功——等于向用户暗示了一个不存在的
       * 控制能力（design.md Capability truth 第 10 条）。
       */
      if (state.capabilities.groupPermissionTier === true) {
        const tier = firstText(state.groupDraft.permissionTier);
        if (tier) body.permission_tier = tier;
        if (Array.isArray(state.groupDraft.permissions)) body.permissions = [...state.groupDraft.permissions];
      }
      await requestJson(GROUPS_ENDPOINT, { method: 'POST', body: JSON.stringify(body) });
      state.saving = false;
      state.groupDraftOpen = false;
      state.groupDraft = {};
      await load();
      if (state.drawer === 'groups') render();
      window.DreamingWrtNotify?.success('用户组已创建');
    } catch (error) {
      state.saving = false;
      const message = firstText(error.message, 'unknown');
      state.notice = /user_group_exists/.test(message) ? '同名用户组已存在' : `创建组失败：${message}`;
      render();
    }
  }

  async function deleteGroup(id) {
    if (!id || state.saving) return;
    state.saving = true;
    state.notice = '';
    render();
    try {
      await requestJson(`${GROUPS_ENDPOINT}/${encodeURIComponent(id)}`, { method: 'DELETE' });
      state.saving = false;
      await load();
      if (state.drawer === 'groups') render();
      window.DreamingWrtNotify?.success('用户组已删除');
    } catch (error) {
      state.saving = false;
      state.notice = `删除组失败：${firstText(error.message, 'unknown')}`;
      render();
    }
  }

  async function importUsers() {
    if (!state.capabilities.import || state.saving || state.importErrors.length) return;
    state.saving = true;
    render();
    try {
      const dryRun = await requestJson(`${USERS_ENDPOINT}/import`, { method: 'POST', body: JSON.stringify({ users: state.importRows, confirm: false }) });
      const dryErrors = asArray(dryRun.errors || [], ['errors']);
      if (dryRun.valid === false || dryErrors.length) {
        state.saving = false;
        state.importErrors = dryErrors.map((item) => `第 ${firstNumber(item.row) || '?'} 行：${firstText(item.message, item.code, '校验失败')}`);
        render();
        return;
      }
      await requestJson(`${USERS_ENDPOINT}/import`, { method: 'POST', body: JSON.stringify({ users: state.importRows, confirm: true }) });
      state.drawer = '';
      state.saving = false;
      await load();
      window.DreamingWrtNotify?.success('用户已导入');
    } catch (error) {
      state.saving = false;
      state.importErrors = [`导入失败：${firstText(error.message, 'unknown')}`];
      render();
    }
  }

  function startPolling() {
    stopPolling();
    state.pollTimer = window.setInterval(() => {
      if (!state.mounted) return;
      if (document.hidden) return;
      if (state.loading || state.saving) return;
      if (state.drawer || state.createMenu) return;
      load();
    }, 20000);
  }

  function stopPolling() {
    if (!state.pollTimer) return;
    window.clearInterval(state.pollTimer);
    state.pollTimer = 0;
  }

  window.addEventListener('dwrt:admin-avatar-changed', onAdminAvatarChanged);
  const wallpaperElement = document.getElementById('appWallpaper');
  wallpaperElement?.addEventListener('load', onWallpaperChange);
  const wallpaperObserver = wallpaperElement && typeof MutationObserver !== 'undefined'
    ? new MutationObserver(onWallpaperChange)
    : null;
  wallpaperObserver?.observe(wallpaperElement, { attributes: true, attributeFilter: ['src', 'style', 'class'] });
  bindDelegatedInputs();
  render();
  load();
  startPolling();
  return { unmount() { state.mounted = false; state.seq += 1; state.activity.seq += 1; stopPolling(); window.removeEventListener('dwrt:admin-avatar-changed', onAdminAvatarChanged); document.removeEventListener('input', onDelegatedInput); document.removeEventListener('change', onDelegatedChange); document.removeEventListener('click', onDelegatedActivityClick); wallpaperElement?.removeEventListener('load', onWallpaperChange); wallpaperObserver?.disconnect(); document.querySelectorAll('.system-users-drawer, .policy-drawer-backdrop[data-system-user-close]').forEach((node) => node.remove()); root?.replaceChildren(); root?.classList.remove(MODULE_CLASS, 'policy-table-route-host', 'route-workspace'); } };
}

export default { mount };
