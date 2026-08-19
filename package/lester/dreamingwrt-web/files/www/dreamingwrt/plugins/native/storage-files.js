export function mount(context = {}) {
  const root = context.root || document.getElementById('routePreview');
  const api = context.api || {};
  const ui = context.ui || {};
  const utils = context.utils || {};
  const escapeHtml = utils.escapeHtml || ((value) => String(value ?? '').replace(/[&<>"']/g, (character) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[character]));
  const VERSION = '20260814-storage-files-403-write-contract-01';
  const ENDPOINT = '/api/v1/storage/files';
  /* 写入是**单入口 + action 分发**，不是每功能一条 REST 路由：后端只有
   * jmx_storage_files_mutate()，action 白名单仅 mkdir/create/write/rename
   * （storage_files.c:1354）。路由字面量后端尚未接出（jmx_app_api.c 里只有两条 GET），
   * 所以这里的路径仍待后端确认，见 Front-to-Backend-storage-files-mutate-route-literal.md。 */
  const MUTATE_ENDPOINT = `${ENDPOINT}/mutate`;
  /* 后端 action 白名单之外的一切写操作都**没有实现**：delete / upload / download_url /
   * permissions / compress / extract / copy / move / install_package 全部不存在端点。
   * 不要再预填这些路由——发出去只会打到一个未注册路径。 */
  const MUTATE_ACTIONS = new Set(['mkdir', 'create', 'write', 'rename']);
  const MODULE_CLASS = 'storage-files-route-host';
  const stage = root?.closest('.console-stage');
  const TEXT_EXTENSIONS = new Set(['txt', 'js', 'ts', 'go', 'py', 'json', 'md', 'html', 'htm', 'css', 'sh', 'bash', 'c', 'cc', 'cpp', 'cxx', 'h', 'hpp', 'hxx', 'java', 'cs', 'php', 'rb', 'rs', 'swift', 'kt', 'kts', 'scala', 'pl', 'pm', 'lua', 'dart', 'yaml', 'yml', 'toml', 'ini', 'conf', 'log', 'rc', 'cfg']);
  const IMAGE_EXTENSIONS = new Set(['jpg', 'jpeg', 'png', 'gif', 'bmp', 'webp', 'svg', 'ico', 'tif', 'tiff', 'avif']);
  const VIDEO_EXTENSIONS = new Set(['mp4', 'webm', 'ogv', 'mov', 'mkv', 'avi', 'flv', 'wmv', 'm4v', '3gp', 'ts']);
  const AUDIO_EXTENSIONS = new Set(['mp3', 'wav', 'ogg', 'flac', 'aac', 'm4a', 'ape', 'amr']);
  const ARCHIVE_EXTENSIONS = ['.zip', '.tar.gz', '.tar.xz', '.tgz'];

  const state = {
    mounted: true,
    seq: 0,
    pollTimer: 0,
    loading: true,
    refreshing: false,
    saving: false,
    loaded: false,
    error: '',
    notice: '',
    noticeTone: '',
    path: '/',
    rootId: '',
    rootPath: '',
    query: '',
    entries: [],
    roots: [],
    capabilities: {},
    limits: {},
    selected: new Set(),
    clipboard: null,
    drawer: '',
    editor: {},
    confirmDelete: false,
    uploadFiles: []
  };

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

  function firstNumber(...values) {
    for (const value of values) {
      if (value === '' || value === undefined || value === null) continue;
      const number = Number(value);
      if (Number.isFinite(number)) return number;
    }
    return 0;
  }

  function bool(value, fallback = false) {
    if (value === undefined || value === null || value === '') return fallback;
    if (typeof value === 'string') return !['0', 'false', 'off', 'no', 'disabled'].includes(value.toLowerCase());
    return Boolean(value);
  }

  function asArray(value, keys = []) {
    if (Array.isArray(value)) return value;
    if (!value || typeof value !== 'object') return [];
    for (const key of [...keys, 'items', 'rows', 'list', 'data']) if (Array.isArray(value[key])) return value[key];
    return [];
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
    return {
      Accept: 'application/json',
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
      ...(typeof api.authHeaders === 'function' ? api.authHeaders() : {}),
      ...extra
    };
  }

  async function requestJson(url, options = {}) {
    const response = await sessionFetch(`${url}${url.includes('?') ? '&' : '?'}v=${VERSION}`, {
      credentials: 'same-origin', cache: 'no-store', ...options,
      headers: authHeaders({ ...(options.body && !(options.body instanceof FormData) ? { 'Content-Type': 'application/json' } : {}), ...(options.headers || {}) })
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

  function normalizePath(value) {
    const input = firstText(value, '/').replace(/\\/g, '/');
    const parts = input.split('/').filter((part) => part && part !== '.');
    const safe = [];
    for (const part of parts) {
      if (part === '..') safe.pop(); else safe.push(part);
    }
    return `/${safe.join('/')}` || '/';
  }

  function joinPath(parent, name) {
    return normalizePath(`${normalizePath(parent)}/${firstText(name)}`);
  }

  function extension(name) {
    const lower = String(name || '').toLowerCase();
    if (lower === 'makefile') return 'makefile';
    return lower.includes('.') ? lower.split('.').pop() : '';
  }

  function symbolicModeToOctal(mode) {
    const text = String(mode || '').trim();
    if (/^0?[0-7]{3,4}$/.test(text)) return text.startsWith('0') ? text : `0${text}`;
    const permissions = text.length >= 9 ? text.slice(-9) : '';
    if (!/^[rwxstST-]{9}$/.test(permissions)) return '';
    const digits = [0, 3, 6].map((offset) => {
      const triad = permissions.slice(offset, offset + 3);
      return (triad[0] === 'r' ? 4 : 0) + (triad[1] === 'w' ? 2 : 0) + (/[xst]/i.test(triad[2]) ? 1 : 0);
    });
    return `0${digits.join('')}`;
  }

  function inferKind(item) {
    if (bool(item.is_dir, item.isdir) || ['directory', 'dir', 'folder'].includes(firstText(item.type, item.kind).toLowerCase())) return 'directory';
    if (bool(item.is_symlink, item.issymlink) || firstText(item.type, item.kind).toLowerCase() === 'symlink') return 'symlink';
    const ext = extension(item.name);
    if (IMAGE_EXTENSIONS.has(ext)) return 'image';
    if (VIDEO_EXTENSIONS.has(ext)) return 'video';
    if (AUDIO_EXTENSIONS.has(ext)) return 'audio';
    if (ARCHIVE_EXTENSIONS.some((suffix) => String(item.name || '').toLowerCase().endsWith(suffix))) return 'archive';
    if (TEXT_EXTENSIONS.has(ext) || String(item.name || '').toLowerCase() === 'makefile') return 'text';
    if (['ipk', 'apk'].includes(ext)) return 'package';
    return firstText(item.kind, item.type, 'file').toLowerCase();
  }

  function normalizeEntry(item, index = 0) {
    const name = firstText(item.name, item.filename, item.basename, `entry-${index + 1}`);
    const path = normalizePath(firstText(item.path, joinPath(state.path, name)));
    const kind = inferKind({ ...item, name });
    return {
      ...item,
      id: firstText(item.id, item.entry_id, path),
      name,
      path,
      kind,
      is_dir: kind === 'directory',
      size_bytes: firstNumber(item.size_bytes, item.size),
      modified_at: firstText(item.modified_at, item.mtime_iso, item.updated_at),
      modified_unix: firstNumber(item.modified_unix, item.mtime, item.modtime),
      mode: firstText(item.mode, item.permissions),
      owner: firstText(item.owner, item.user),
      group: firstText(item.group),
      link_target: firstText(item.link_target, item.linktarget, item.target),
      hidden: bool(item.hidden, name.startsWith('.')),
      mime: firstText(item.mime, item.content_type),
      capabilities: item.capabilities || {}
    };
  }

  function normalizeRoot(item, index = 0) {
    if (typeof item === 'string') {
      const only = normalizePath(item);
      return { id: item, label: only === '/' ? '根文件系统' : only, path: only, read_only: false, total_bytes: 0, available_bytes: 0 };
    }
    const path = normalizePath(firstText(item.path, item.mount_point, item.root, '/'));
    return {
      ...item,
      id: firstText(item.id, item.uuid, path, `root-${index + 1}`),
      /* 后端 label 就是挂载路径，`/` 直接显示成 "/" 用户读不出含义，只对它换成中文名。 */
      label: path === '/' ? '根文件系统' : firstText(item.label, item.name, path),
      path,
      read_only: bool(item.read_only, false),
      total_bytes: firstNumber(item.total_bytes, item.total, item.size_bytes),
      available_bytes: firstNumber(item.available_bytes, item.available, item.free_bytes)
    };
  }

  function rootById(id) {
    return state.roots.find((item) => item.id === id) || null;
  }

  function currentRoot() {
    return rootById(state.rootId);
  }

  function isReadOnlyRoot() {
    /* 只读判定只认接口下发的 read_only。不要在前端维护路径清单：分级由后端
     * storage_files_root_write_protected() 决定，硬编码必然与后端漂移。 */
    return currentRoot()?.read_only === true;
  }

  /* 后端把「根内相对路径」拼在 root.path 后面，根为 `/` 时结果是 `//etc` 这种双斜杠形式，
   * 而且它只接受这一形式：请求 `/etc` 会被判成 invalid_relative_path。所以对外发出的
   * path 必须按当前根重新拼装，不能用 normalizePath 把 `//` 压成 `/`。 */
  function apiPath(path, root = currentRoot()) {
    const target = firstText(path, '/');
    if (!root || root.path !== '/') return normalizePath(target);
    const relative = target.replace(/^\/+/, '');
    return relative ? `//${relative}` : '/';
  }

  /* 面包屑与标题用的可读路径：把后端的 `//etc` 显示成 `/etc`。 */
  function displayPath(path) {
    return normalizePath(path);
  }

  function normalizePayload(payload = {}) {
    const source = payload.files && typeof payload.files === 'object' ? payload.files : payload;
    return {
      path: normalizePath(firstText(source.path, source.cwd, source.directory, state.path)),
      rootId: firstText(source.root_id, source.rootId),
      entries: asArray(source.entries, ['files', 'items']).map(normalizeEntry),
      roots: asArray(source.roots, ['volumes', 'mounts']).map(normalizeRoot),
      capabilities: source.capabilities && typeof source.capabilities === 'object' ? source.capabilities : {},
      limits: source.limits && typeof source.limits === 'object' ? source.limits : {}
    };
  }

  /* 每个根都是独立的 root_id，且路径遍历带 RESOLVE_NO_XDEV：从 `/` 进不去 `/data`，
   * 必须用 /data 自己的 root_id 进入。所以任何一次列目录都要带上 root_id，
   * 只传 path 会让用户卡在默认根里。 */
  async function load(path = state.path, background = false, rootId = state.rootId) {
    const seq = ++state.seq;
    const targetRoot = rootById(rootId);
    const nextPath = normalizePath(path);
    const query = [`path=${encodeURIComponent(apiPath(nextPath, targetRoot))}`];
    if (rootId) query.push(`root_id=${encodeURIComponent(rootId)}`);
    if (background) state.refreshing = true; else state.loading = true;
    state.error = '';
    render();
    try {
      const payload = normalizePayload(await requestJson(`${ENDPOINT}?${query.join('&')}`));
      if (!state.mounted || seq !== state.seq) return;
      state.path = payload.path;
      state.entries = payload.entries;
      state.roots = payload.roots;
      state.rootId = payload.rootId || rootId;
      state.rootPath = rootById(state.rootId)?.path || '';
      state.capabilities = payload.capabilities;
      state.limits = payload.limits;
      state.selected.clear();
      state.loaded = true;
    } catch (error) {
      if (!state.mounted || seq !== state.seq) return;
      state.path = nextPath;
      state.entries = [];
      state.error = loadErrorText(error);
    } finally {
      if (!state.mounted || seq !== state.seq) return;
      state.loading = false;
      state.refreshing = false;
      if (background) renderPreservingInteraction(); else render();
    }
  }

  /* 后端的失败原因是有意义的语义，不要一律说成「接口尚未开放」——那会把越界防护
   * 和真正的后端缺失混成一句话，用户无从判断。 */
  function loadErrorText(error) {
    const message = firstText(error?.message);
    if (/storage_root_not_found/.test(message)) return '该路径不属于任何可访问的存储根。请从上方存储位置里选择一个根。';
    if (/mount_boundary_rejected/.test(message)) return '该目录是另一个挂载点，出于越界防护不能从当前存储根进入。请在上方存储位置里直接选择它。';
    if (/invalid_relative_path/.test(message)) return '该路径不在当前存储根范围内。请切换到对应的存储位置。';
    if (/directory_unavailable/.test(message)) return '目录无法打开，可能已被删除或没有读取权限。';
    if (/mount_inventory_unavailable/.test(message)) return '无法读取挂载表，暂时列不出存储根。';
    if (error?.status === 401) return '会话已过期，请重新登录后再查看。';
    return message ? `读取目录失败：${message}` : '读取目录失败。';
  }

  function hasCapability(action, entry = null) {
    const local = entry?.capabilities || {};
    return local[action] === true || state.capabilities[action] === true || state.capabilities[`file_${action}`] === true;
  }

  /* 对齐后端 storage_files_safe_name()（storage_files.c:1200）：单个路径分量，
   * 不能是 . 或 ..，不含控制字符、`/`、`\`，长度 <= NAME_MAX，且不能占用事务前缀。
   * 这是提前拦一次以免用户点了才被拒；判定权仍在后端，前端不放宽任何一条。 */
  function isSafeName(value) {
    const name = String(value ?? '');
    if (!name || name === '.' || name === '..') return false;
    if (name.length > 255) return false;
    if (name.startsWith('.dreamingwrt-tx-')) return false;
    return !/[/\\]/.test(name) && !/[\u0000-\u001f]/.test(name);
  }

  function icon(name) {
    const paths = {
      search: '<circle cx="11" cy="11" r="7"></circle><path d="m16.5 16.5 4 4"></path>',
      refresh: '<path d="M20 11a8 8 0 1 0 1 4"></path><path d="M20 4v7h-7"></path>',
      upload: '<path d="M12 16V4m-5 5 5-5 5 5"></path><path d="M4 20h16"></path>',
      plus: '<path d="M12 5v14M5 12h14"></path>',
      folder: '<path d="M3 6h7l2 2h9v10a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2Z"></path>',
      file: '<path d="M6 2h8l4 4v16H6z"></path><path d="M14 2v5h5"></path>',
      image: '<rect x="3" y="4" width="18" height="16" rx="2"></rect><circle cx="8.5" cy="9" r="1.5"></circle><path d="m21 15-5-5L5 20"></path>',
      video: '<rect x="3" y="5" width="18" height="14" rx="2"></rect><path d="m10 9 5 3-5 3Z"></path>',
      audio: '<path d="M9 18V5l10-2v13"></path><circle cx="6" cy="18" r="3"></circle><circle cx="16" cy="16" r="3"></circle>',
      archive: '<path d="M6 2h12v20H6z"></path><path d="M10 2v3h3V8h-3v3h3v3h-3v3h3"></path>',
      package: '<path d="m12 3 8 4.5v9L12 21l-8-4.5v-9Z"></path><path d="m4 7.5 8 4.5 8-4.5M12 12v9"></path>',
      link: '<path d="M10 13a5 5 0 0 0 7.5.5l2-2a5 5 0 0 0-7-7l-1.2 1.2"></path><path d="M14 11a5 5 0 0 0-7.5-.5l-2 2a5 5 0 0 0 7 7l1.2-1.2"></path>',
      copy: '<rect x="8" y="8" width="12" height="12" rx="2"></rect><path d="M16 8V5a1 1 0 0 0-1-1H5a1 1 0 0 0-1 1v10a1 1 0 0 0 1 1h3"></path>',
      cut: '<circle cx="6" cy="7" r="3"></circle><circle cx="6" cy="17" r="3"></circle><path d="m8.7 8.4 11.3 6M8.7 15.6 20 10"></path>',
      paste: '<path d="M9 4h6l1 3H8z"></path><path d="M7 6H5v16h14V6h-2"></path>',
      download: '<path d="M12 3v12m-5-5 5 5 5-5"></path><path d="M5 21h14"></path>',
      compress: '<path d="M6 2h12v20H6z"></path><path d="M10 2v3h3V8h-3v3h3v3h-3v3h3"></path>',
      edit: '<path d="m4 20 4.2-1 10.9-10.9a2 2 0 0 0-2.8-2.8L5.4 16.2 4 20Z"></path>',
      lock: '<rect x="5" y="10" width="14" height="11" rx="2"></rect><path d="M8 10V7a4 4 0 0 1 8 0v3"></path>',
      trash: '<path d="M4 7h16M9 7V4h6v3m-9 0 1 13h10l1-13M10 11v5m4-5v5"></path>',
      chevron: '<path d="m9 18 6-6-6-6"></path>',
      home: '<path d="m3 11 9-8 9 8"></path><path d="M5 10v11h14V10M9 21v-7h6v7"></path>',
      more: '<circle cx="5" cy="12" r="1"></circle><circle cx="12" cy="12" r="1"></circle><circle cx="19" cy="12" r="1"></circle>'
    };
    return `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${paths[name] || paths.file}</svg>`;
  }

  function formatBytes(value) {
    const bytes = Number(value || 0);
    if (!Number.isFinite(bytes) || bytes < 0) return '--';
    if (bytes === 0) return '0 B';
    const units = ['B', 'KB', 'MB', 'GB', 'TB', 'PB'];
    const index = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1);
    const amount = bytes / (1024 ** index);
    return `${amount >= 100 || index === 0 ? amount.toFixed(0) : amount >= 10 ? amount.toFixed(1) : amount.toFixed(2)} ${units[index]}`;
  }

  function formatTime(entry) {
    const input = entry.modified_at || (entry.modified_unix ? entry.modified_unix * 1000 : 0);
    if (!input) return '--';
    const date = new Date(input);
    if (Number.isNaN(date.getTime())) return firstText(input, '--');
    return new Intl.DateTimeFormat('zh-CN', { year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit' }).format(date);
  }

  /* 面包屑必须以当前根为起点，不能从 `/` 逐级拆。跨根的中间层级（例如 /etc/config 根
   * 的 /etc）并不属于本根，点进去只会拿到 invalid_relative_path。 */
  function breadcrumbMarkup() {
    const root = currentRoot();
    const rootPath = root?.path || '/';
    const here = displayPath(state.path);
    const rootLabel = root ? root.label : '根目录';
    const crumbs = [`<button type="button" data-file-path="${escapeHtml(rootPath)}" aria-label="${escapeHtml(rootLabel)}">${icon('home')}<span>${escapeHtml(rootLabel)}</span></button>`];
    const tail = rootPath === '/' ? here : here.slice(rootPath.length);
    let current = rootPath === '/' ? '' : rootPath;
    tail.split('/').filter(Boolean).forEach((part) => {
      current = `${current}/${part}`;
      crumbs.push(`<span>${icon('chevron')}</span><button type="button" data-file-path="${escapeHtml(current)}">${escapeHtml(part)}</button>`);
    });
    return `<nav class="storage-file-breadcrumb" aria-label="文件路径">${crumbs.join('')}</nav>`;
  }

  /* 窄屏下选择器只有 102px，容量后缀会把根名挤成「根文件系统 ·」这种截断，
   * 根名反而看不全。窄屏只保留根名与只读标记。 */
  function rootOptionLabel(item) {
    /* 窄屏下选择器只有 102px：容量和只读后缀会把根名截断成「根文件系统 ·」，
     * 根名反而看不全。窄屏只留根名，只读状态由旁边的徽标承担。 */
    const compact = typeof window.matchMedia === 'function' && window.matchMedia('(max-width: 800px)').matches;
    if (compact) return item.label;
    const capacity = item.total_bytes ? `${formatBytes(item.available_bytes)} 可用 / ${formatBytes(item.total_bytes)}` : '';
    return [item.label, item.read_only ? '只读' : '', capacity].filter(Boolean).join(' · ');
  }

  function rootsMarkup() {
    if (!state.roots.length) return '';
    const options = state.roots.map((item) => `<option value="${escapeHtml(item.id)}" ${item.id === state.rootId ? 'selected' : ''}>${escapeHtml(rootOptionLabel(item))}</option>`).join('');
    return `<label class="storage-file-root-field dwrt-kit-field" data-dwrt-component="field"><select class="storage-file-root-select" data-file-root aria-label="存储位置">${options}</select></label>${isReadOnlyRoot() ? '<span class="storage-file-root-badge" data-dwrt-tooltip="该存储根只读，写入类操作已隐藏">只读</span>' : ''}`;
  }

  function toolbarMarkup() {
    const count = state.selected.size;
    const canPaste = Boolean(state.clipboard?.paths?.length) && hasCapability(state.clipboard.action === 'cut' ? 'move' : 'copy');
    /* 只读根上不给写入入口：后端会拒，但让用户点了才被拒是差的体验。 */
    const readOnly = isReadOnlyRoot();
    const writeActions = readOnly ? '' : `<button class="policy-filter-button" type="button" data-file-cut ${count ? '' : 'disabled'}>${icon('cut')}<span>剪切</span></button><button class="policy-filter-button" type="button" data-file-paste ${canPaste ? '' : 'disabled'}>${icon('paste')}<span>粘贴</span></button>`;
    /* 压缩会在当前目录写出归档文件，所以它跟删除一样属于写入类，只读根上一并隐藏。 */
    const destructiveActions = readOnly ? '' : `<button class="policy-filter-button" type="button" data-file-compress ${count ? '' : 'disabled'}>${icon('compress')}<span>压缩</span></button><button class="policy-filter-button danger" type="button" data-file-delete-selected ${count ? '' : 'disabled'}>${icon('trash')}<span>删除</span></button>`;
    const createActions = readOnly
      ? '<span class="storage-file-readonly-hint"><span class="is-long">此存储根只读，仅可浏览与查看</span><span class="is-short">只读，仅可浏览</span></span>'
      : `<button class="policy-filter-button" type="button" data-file-upload>${icon('upload')}<span>上传</span></button><button class="policy-create-button" type="button" data-file-new>${icon('plus')}<span>新建</span></button>`;
    /*
     * 页面级 header 只留导航（存储根 + 面包屑）。搜索与动作按钮属于表格工具栏，
     * 由 `tableActionsMarkup()` 渲染进 `.dwrt-kit-table-toolbar`（design.md 规则 15）。
     */
    return `<header class="storage-file-toolbar"><div class="storage-file-toolbar-top">${rootsMarkup()}${breadcrumbMarkup()}</div></header>`;
  }

  /* 表格工具栏里的搜索与动作。与 toolbarMarkup() 共用同一批 data-* 钩子。 */
  function tableActionsMarkup() {
    const count = state.selected.size;
    const canPaste = Boolean(state.clipboard?.paths?.length) && hasCapability(state.clipboard.action === 'cut' ? 'move' : 'copy');
    const readOnly = isReadOnlyRoot();
    const writeActions = readOnly ? '' : `<button class="policy-filter-button" type="button" data-file-cut ${count ? '' : 'disabled'}>${icon('cut')}<span>剪切</span></button><button class="policy-filter-button" type="button" data-file-paste ${canPaste ? '' : 'disabled'}>${icon('paste')}<span>粘贴</span></button>`;
    const destructiveActions = readOnly ? '' : `<button class="policy-filter-button" type="button" data-file-compress ${count ? '' : 'disabled'}>${icon('compress')}<span>压缩</span></button><button class="policy-filter-button danger" type="button" data-file-delete-selected ${count ? '' : 'disabled'}>${icon('trash')}<span>删除</span></button>`;
    const createActions = readOnly
      ? '<span class="storage-file-readonly-hint"><span class="is-long">此存储根只读，仅可浏览与查看</span><span class="is-short">只读，仅可浏览</span></span>'
      : `<button class="policy-filter-button" type="button" data-file-upload>${icon('upload')}<span>上传</span></button><button class="policy-create-button" type="button" data-file-new>${icon('plus')}<span>新建</span></button>`;
    return `<div class="storage-file-table-actions"><label class="policy-search policy-search-main storage-file-search" data-dwrt-component="expand-search"><span class="dwrt-kit-expand-search-original-icon">${icon('search')}</span><input type="search" data-file-search value="${escapeHtml(state.query)}" placeholder="搜索文件或文件夹"></label><div class="storage-file-selection-actions"><button class="policy-filter-button" type="button" data-file-copy ${count ? '' : 'disabled'}>${icon('copy')}<span>复制</span></button>${writeActions}${destructiveActions}</div><div class="policy-toolbar-actions">${createActions}</div></div>`;
  }

  function kindIcon(kind) {
    if (kind === 'directory') return 'folder';
    if (kind === 'image') return 'image';
    if (kind === 'video') return 'video';
    if (kind === 'audio') return 'audio';
    if (kind === 'archive') return 'archive';
    if (kind === 'package') return 'package';
    if (kind === 'symlink') return 'link';
    return 'file';
  }

  function filteredEntries() {
    const query = state.query.trim().toLowerCase();
    return state.entries.filter((entry) => !query || [entry.name, entry.path, entry.mode, entry.owner, entry.group, entry.link_target].join(' ').toLowerCase().includes(query));
  }

  function rowActionMarkup(entry) {
    const readOnly = isReadOnlyRoot();
    const head = entry.kind === 'archive' && !readOnly
      ? `<button type="button" data-file-extract="${escapeHtml(entry.id)}" aria-label="解压" data-dwrt-tooltip="解压">${icon('archive')}</button>`
      : !entry.is_dir
        ? `<button type="button" data-file-download="${escapeHtml(entry.id)}" aria-label="下载" data-dwrt-tooltip="下载">${icon('download')}</button>`
        : '';
    /* 只读根上重命名/改权限/删除全部隐藏；解压同理，它写入目标目录。 */
    const mutating = readOnly ? '' : `<button type="button" data-file-rename="${escapeHtml(entry.id)}" aria-label="重命名" data-dwrt-tooltip="重命名">${icon('edit')}</button><button type="button" data-file-permissions="${escapeHtml(entry.id)}" aria-label="权限与属主" data-dwrt-tooltip="权限与属主">${icon('lock')}</button><button class="danger" type="button" data-file-delete="${escapeHtml(entry.id)}" aria-label="删除" data-dwrt-tooltip="删除">${icon('trash')}</button>`;
    const locked = readOnly && !head && !mutating ? `<span class="storage-file-row-locked" data-dwrt-tooltip="只读存储根">${icon('lock')}</span>` : '';
    return `<div class="storage-file-row-actions">${head}${mutating}${locked}</div>`;
  }

  function tableMarkup() {
    const entries = filteredEntries();
    const rows = entries.map((entry) => {
      const selected = state.selected.has(entry.id);
      const target = entry.is_dir ? 'directory' : ['text', 'image', 'video', 'audio', 'package'].includes(entry.kind) ? entry.kind : 'download';
      return `<tr class="${selected ? 'is-selected' : ''}" data-file-row="${escapeHtml(entry.id)}"><td><input type="checkbox" data-file-select="${escapeHtml(entry.id)}" ${selected ? 'checked' : ''} aria-label="选择 ${escapeHtml(entry.name)}"></td><td><button class="storage-file-name" type="button" data-file-open="${escapeHtml(entry.id)}" data-file-target="${target}"><span class="is-${escapeHtml(entry.kind)}">${icon(kindIcon(entry.kind))}</span><span><strong>${escapeHtml(entry.name)}</strong>${entry.link_target ? `<small>→ ${escapeHtml(entry.link_target)}</small>` : ''}</span></button></td><td>${entry.is_dir ? '--' : formatBytes(entry.size_bytes)}</td><td>${escapeHtml(formatTime(entry))}</td><td><code>${escapeHtml(entry.mode || '--')}</code></td><td>${escapeHtml([entry.owner, entry.group].filter(Boolean).join('/') || '--')}</td><td>${rowActionMarkup(entry)}</td></tr>`;
    });
    const empty = state.loading && !state.loaded ? '正在读取目录' : state.error ? state.error : state.query ? '没有符合搜索条件的文件' : '此目录为空';
    const allSelected = entries.length > 0 && entries.every((entry) => state.selected.has(entry.id));
    return `<section class="storage-file-table-card dwrt-kit-table-wrap dwrt-kit-ikuai-table-wrap dwrt-kit-glass-surface"><div class="dwrt-kit-table-toolbar"><div class="dwrt-kit-table-title"><strong>${escapeHtml(displayPath(state.path))}</strong>${state.selected.size ? `<span>已选择 ${state.selected.size} 项</span>` : ''}</div><span class="dwrt-kit-table-count">${entries.length} 项</span>${tableActionsMarkup()}</div><div class="dwrt-kit-table-scroll"><table class="dwrt-kit-table dwrt-kit-ikuai-table storage-file-table"><thead><tr><th><input type="checkbox" data-file-select-all ${allSelected ? 'checked' : ''} ${entries.length ? '' : 'disabled'} aria-label="全选"></th><th>名称</th><th>大小</th><th>修改时间</th><th>权限</th><th>属主</th><th>操作</th></tr></thead><tbody>${rows.length ? rows.join('') : `<tr><td colspan="7" class="dwrt-kit-table-empty">${escapeHtml(empty)}</td></tr>`}</tbody></table></div></section>`;
  }

  function noticeMarkup() {
    const text = state.notice || state.error;
    if (!text) return '';
    return `<div class="storage-file-notice is-${escapeHtml(state.notice ? state.noticeTone || 'info' : 'warning')}">${escapeHtml(text)}</div>`;
  }

  function field(label, path, value, options = {}) {
    const control = options.options
      ? `<select data-file-draft="${escapeHtml(path)}">${options.options.map(([id, text]) => `<option value="${escapeHtml(id)}" ${String(value) === String(id) ? 'selected' : ''}>${escapeHtml(text)}</option>`).join('')}</select>`
      : options.multiline
        ? `<textarea data-file-draft="${escapeHtml(path)}" ${options.readonly ? 'readonly' : ''} placeholder="${escapeHtml(options.placeholder || '')}">${escapeHtml(value || '')}</textarea>`
        : `<input data-file-draft="${escapeHtml(path)}" value="${escapeHtml(value || '')}" ${options.type ? `type="${escapeHtml(options.type)}"` : ''} placeholder="${escapeHtml(options.placeholder || '')}" ${options.readonly ? 'readonly' : ''}>`;
    return `<label class="storage-file-field dwrt-kit-field ${options.wide ? 'is-wide' : ''}" data-dwrt-component="field"><span>${escapeHtml(label)}</span>${control}${options.help ? `<small>${escapeHtml(options.help)}</small>` : ''}</label>`;
  }

  function drawerTitle() {
    const map = { new: '新建', upload: '添加文件', rename: '重命名', permissions: '权限与属主', compress: '压缩', extract: '解压', delete: '删除', editor: state.editor.name || '编辑文件', preview: state.editor.name || '文件预览', package: '安装软件包' };
    return map[state.drawer] || '文件管理';
  }

  function newDrawerBody() {
    return `<div class="storage-file-choice-grid"><button type="button" data-file-new-kind="directory">${icon('folder')}<span><strong>新建文件夹</strong><small>在当前目录创建文件夹</small></span></button><button type="button" data-file-new-kind="file">${icon('file')}<span><strong>新建文件</strong><small>创建空文件后可继续编辑</small></span></button></div>${state.editor.kind ? `<div class="storage-file-form">${field(state.editor.kind === 'directory' ? '文件夹名称' : '文件名称', 'name', state.editor.name, { wide: true, placeholder: state.editor.kind === 'directory' ? '新建文件夹' : 'new-file.txt' })}</div>${!hasCapability(state.editor.kind === 'directory' ? 'mkdir' : 'create') ? '<div class="storage-file-capability">后端新建能力尚未开放。</div>' : ''}` : '<div class="storage-file-empty-hint" data-dwrt-component="state-panel" data-dwrt-state="empty" data-dwrt-surface="dense-surface">请选择要创建的类型</div>'}${state.notice ? noticeMarkup() : ''}`;
  }

  function uploadDrawerBody() {
    const files = state.uploadFiles;
    const max = firstNumber(state.limits.max_upload_bytes);
    const mode = state.editor.mode || 'local';
    const local = `<label class="storage-file-dropzone"><input type="file" multiple data-file-upload-input><span>${icon('upload')}</span><strong>选择要上传的文件</strong><small>上传到 ${escapeHtml(state.path)}${max ? ` · 单文件上限 ${formatBytes(max)}` : ''}</small></label><div class="storage-file-upload-list">${files.length ? files.map((file) => `<div><span>${icon('file')}</span><span><strong>${escapeHtml(file.name)}</strong><small>${formatBytes(file.size)}</small></span></div>`).join('') : '<div class="storage-file-empty-hint" data-dwrt-component="state-panel" data-dwrt-state="empty" data-dwrt-surface="dense-surface">尚未选择文件</div>'}</div>${!hasCapability('upload') ? '<div class="storage-file-capability">后端上传能力尚未开放。浏览器不会把文件发送到其他地址。</div>' : ''}`;
    const remote = `<div class="storage-file-form">${field('下载地址', 'url', state.editor.url, { wide: true, type: 'url', placeholder: 'https://example.com/file.bin', help: '后端必须限制协议、重定向、目标地址和下载大小，防止访问内网元数据或本机管理接口。' })}${field('保存文件名', 'name', state.editor.name, { wide: true, placeholder: 'file.bin' })}</div>${!hasCapability('download_url') ? '<div class="storage-file-capability">后端 URL 下载能力尚未开放。</div>' : ''}`;
    return `<div class="storage-file-segmented" role="group" aria-label="添加文件方式"><button type="button" class="${mode === 'local' ? 'is-active' : ''}" data-file-upload-mode="local">本地上传</button><button type="button" class="${mode === 'url' ? 'is-active' : ''}" data-file-upload-mode="url">URL 下载</button></div>${mode === 'local' ? local : remote}${state.notice ? noticeMarkup() : ''}`;
  }

  function renameDrawerBody() {
    const entry = state.editor.entry;
    /* 后端 rename 前置检查要求目标是 regular file（:1474 判 S_ISREG），目录改不了名；
     * new_name 走 safe_name()，含 / 直接拒，所以只能同目录改名，不能跨目录移动。 */
    const unsupported = entry?.is_dir
      ? '<div class="storage-file-capability">当前固件只支持文件改名，目录改名尚未开放。</div>'
      : !hasCapability('rename', entry)
        ? '<div class="storage-file-capability">后端重命名能力尚未开放。</div>'
        : '';
    return `<div class="storage-file-target"><span>${icon(kindIcon(entry?.kind))}</span><div><strong>${escapeHtml(entry?.name || '--')}</strong><small>${escapeHtml(entry?.path || state.path)}</small></div></div><div class="storage-file-form">${field('新名称', 'name', state.editor.name, { wide: true, help: '只能在当前目录内改名，不能含 / 。' })}</div>${unsupported}${state.notice ? noticeMarkup() : ''}`;
  }

  function permissionsDrawerBody() {
    const entry = state.editor.entry;
    return `<div class="storage-file-target"><span>${icon(kindIcon(entry?.kind))}</span><div><strong>${escapeHtml(entry?.name || '--')}</strong><small>${escapeHtml(entry?.path || state.path)}</small></div></div><div class="storage-file-form">${field('权限', 'mode', state.editor.mode, { placeholder: '例如 0644', help: '使用八进制权限；后端必须拒绝非法或越权值。' })}${field('用户', 'owner', state.editor.owner, { placeholder: '用户名' })}${field('用户组', 'group', state.editor.group, { placeholder: '用户组（可选）' })}</div>${!hasCapability('permissions', entry) ? '<div class="storage-file-capability">后端权限与属主修改能力尚未开放。</div>' : ''}${state.notice ? noticeMarkup() : ''}`;
  }

  function compressDrawerBody() {
    const names = selectedEntries().map((entry) => entry.name);
    return `<div class="storage-file-selected-list">${names.map((name) => `<span>${escapeHtml(name)}</span>`).join('')}</div><div class="storage-file-form">${field('压缩格式', 'format', state.editor.format, { options: [['zip', 'ZIP'], ['tar.gz', 'TAR.GZ'], ['tar.xz', 'TAR.XZ']] })}${field('文件名', 'name', state.editor.name)}</div>${!hasCapability('compress') ? '<div class="storage-file-capability">后端压缩能力尚未开放。</div>' : ''}${state.notice ? noticeMarkup() : ''}`;
  }

  function extractDrawerBody() {
    const entry = state.editor.entry;
    return `<div class="storage-file-target"><span>${icon('archive')}</span><div><strong>${escapeHtml(entry?.name || '--')}</strong><small>${escapeHtml(entry?.path || state.path)}</small></div></div><div class="storage-file-form">${field('解压到', 'destination', state.editor.destination, { wide: true, placeholder: state.path, help: '后端必须阻止压缩包中的绝对路径、.. 越界路径、特殊文件和越界符号链接。' })}</div>${!hasCapability('extract', entry) ? '<div class="storage-file-capability">后端解压能力尚未开放。</div>' : ''}${state.notice ? noticeMarkup() : ''}`;
  }

  function deleteDrawerBody() {
    const entries = state.editor.entries || [];
    return `<div class="storage-file-danger-copy"><span>${icon('trash')}</span><div><strong>删除 ${entries.length} 个项目</strong><p>目录删除应由后端拒绝系统关键路径、挂载点、非空受保护目录及越界符号链接。</p></div></div><div class="storage-file-selected-list">${entries.map((entry) => `<span>${escapeHtml(entry.path)}</span>`).join('')}</div>${!entries.every((entry) => hasCapability('delete', entry)) ? '<div class="storage-file-capability">后端删除能力尚未开放。</div>' : ''}${state.notice ? noticeMarkup() : ''}`;
  }

  function editorDrawerBody() {
    const entry = state.editor.entry;
    const meta = `<div class="storage-file-editor-meta"><code>${escapeHtml(displayPath(entry?.path || ''))}</code><span>${formatBytes(entry?.size_bytes)}</span></div>`;
    /* 内容被安全策略拒绝时不要摆一个空编辑器：那会被读成「文件是空的」。 */
    if (state.editor.contentError) return `${meta}<div class="storage-file-content-blocked">${icon('lock')}<div><strong>内容不可显示</strong><p>${escapeHtml(state.editor.contentError)}</p></div></div>`;
    return `${meta}<label class="storage-file-editor"><textarea data-file-draft="content" spellcheck="false" ${state.editor.loadingContent ? 'disabled' : ''}>${escapeHtml(state.editor.content || '')}</textarea></label>${!hasCapability('write', entry) ? '<div class="storage-file-capability">后端文本写入能力尚未开放。可以查看内容，但保存按钮保持禁用。</div>' : ''}${state.notice ? noticeMarkup() : ''}`;
  }

  function previewDrawerBody() {
    const entry = state.editor.entry;
    const src = `${ENDPOINT}/content?path=${encodeURIComponent(apiPath(entry?.path || ''))}${state.rootId ? `&root_id=${encodeURIComponent(state.rootId)}` : ''}&v=${VERSION}`;
    if (entry?.kind === 'image') return `<div class="storage-file-media"><img src="${escapeHtml(src)}" alt="${escapeHtml(entry.name)}"></div>`;
    if (entry?.kind === 'video') return `<div class="storage-file-media"><video src="${escapeHtml(src)}" controls></video></div>`;
    if (entry?.kind === 'audio') return `<div class="storage-file-media is-audio"><span>${icon('audio')}</span><strong>${escapeHtml(entry.name)}</strong><audio src="${escapeHtml(src)}" controls></audio></div>`;
    return '<div class="storage-file-empty-hint" data-dwrt-component="state-panel" data-dwrt-state="empty" data-dwrt-surface="dense-surface">此文件类型不支持预览</div>';
  }

  function packageDrawerBody() {
    const entry = state.editor.entry;
    return `<div class="storage-file-danger-copy is-package"><span>${icon('package')}</span><div><strong>${escapeHtml(entry?.name || '软件包')}</strong><p>安装软件包会修改系统。软件源更新、安装日志与结果必须由后端任务返回，不能在前端执行 shell 命令。</p></div></div>${!hasCapability('install_package', entry) ? '<div class="storage-file-capability">后端软件包安装能力尚未开放。</div>' : ''}${state.notice ? noticeMarkup() : ''}`;
  }

  function drawerBody() {
    if (state.drawer === 'new') return newDrawerBody();
    if (state.drawer === 'upload') return uploadDrawerBody();
    if (state.drawer === 'rename') return renameDrawerBody();
    if (state.drawer === 'permissions') return permissionsDrawerBody();
    if (state.drawer === 'compress') return compressDrawerBody();
    if (state.drawer === 'extract') return extractDrawerBody();
    if (state.drawer === 'delete') return deleteDrawerBody();
    if (state.drawer === 'editor') return editorDrawerBody();
    if (state.drawer === 'preview') return previewDrawerBody();
    if (state.drawer === 'package') return packageDrawerBody();
    return '';
  }

  function drawerCanSave() {
    if (state.drawer === 'new') return Boolean(state.editor.kind && isSafeName(state.editor.name) && hasCapability(state.editor.kind === 'directory' ? 'mkdir' : 'create'));
    if (state.drawer === 'upload') return state.editor.mode === 'url' ? Boolean(state.editor.url && state.editor.name && hasCapability('download_url')) : state.uploadFiles.length > 0 && hasCapability('upload');
    /* 目录改名后端不支持，名字含 / 或 \ 会被 safe_name() 拒，两者都不给点保存。 */
    if (state.drawer === 'rename') return Boolean(state.editor.name && !state.editor.entry?.is_dir && isSafeName(state.editor.name) && hasCapability('rename', state.editor.entry));
    if (state.drawer === 'permissions') return Boolean(state.editor.mode && hasCapability('permissions', state.editor.entry));
    if (state.drawer === 'compress') return Boolean(state.editor.name && hasCapability('compress'));
    if (state.drawer === 'extract') return Boolean(state.editor.destination && hasCapability('extract', state.editor.entry));
    if (state.drawer === 'delete') return Boolean((state.editor.entries || []).length && state.editor.entries.every((entry) => hasCapability('delete', entry)));
    /* 没有 etag 就点不动保存：后端 write 必填 expected_etag（:1516），
     * 少了它必然 expected_etag_required，让用户点了才失败是差的体验。 */
    if (state.drawer === 'editor') return hasCapability('write', state.editor.entry) && !state.editor.loadingContent && Boolean(state.editor.etag);
    if (state.drawer === 'package') return hasCapability('install_package', state.editor.entry);
    return false;
  }

  function drawerSaveLabel() {
    if (state.saving) return '正在处理';
    const map = { new: '创建', upload: state.editor.mode === 'url' ? '开始下载' : '开始上传', rename: '保存', permissions: '应用', compress: '开始压缩', extract: '开始解压', delete: state.confirmDelete ? '确认删除' : '删除', editor: '保存文件', package: '安装' };
    return drawerCanSave() ? map[state.drawer] || '保存' : state.drawer === 'preview' ? '' : '等待后端能力';
  }

  function drawerMarkup() {
    if (!state.drawer) return '';
    /* 内容被安全策略拒绝时没有可保存的东西，按预览处理，footer 只留「关闭」，
     * 否则会显示成「等待后端能力」——那是错的归因，后端能力在，是策略拒绝。 */
    const readonly = state.drawer === 'preview' || (state.drawer === 'editor' && Boolean(state.editor.contentError));
    return `<button class="dwrt-kit-sheet-overlay is-open" type="button" data-file-close aria-label="关闭文件管理面板"></button><aside class="storage-file-drawer dwrt-kit-sheet dwrt-kit-glass-surface is-open" aria-label="${escapeHtml(drawerTitle())}"><header class="dwrt-kit-sheet-header"><div><span>FILE MANAGER</span><strong>${escapeHtml(drawerTitle())}</strong></div><button class="dwrt-kit-sheet-close" type="button" data-file-close aria-label="关闭">×</button></header><div class="dwrt-kit-sheet-body storage-file-drawer-body">${drawerBody()}</div><footer class="dwrt-kit-sheet-footer storage-file-drawer-footer"><span></span><div><button class="policy-secondary" type="button" data-file-close>${readonly ? '关闭' : '取消'}</button>${readonly ? '' : `<button class="policy-primary ${state.drawer === 'delete' ? 'danger' : ''}" type="button" data-file-save ${drawerCanSave() && !state.saving ? '' : 'disabled'}>${drawerSaveLabel()}</button>`}</div></footer></aside>`;
  }

  /*
   * 轮询刷新走 kit 的共享保状态入口（Acceptance P0 单：30.1 实机 45 路由巡检，20 条路由在
   * 一个轮询周期里丢滚动 / 焦点 / 选区，根因是整树重绘）。用户主动操作仍走 render()：
   * 那时候 DOM 本来就应该变。
   *
   * render() 收一个可选目标：kit 会先让它渲进离屏容器，再按语义 key patch 回真实 DOM，
   * 未变化的节点不换身份。宿主级设置（hidden / class）仍作用在真实 root 上，因为那些是
   * 路由容器自身的状态，不属于本次要 patch 的内容。
   */
  function renderPreservingInteraction() {
    const preserve = ui.preserveInteractionState;
    if (typeof preserve === 'function' && preserve(root, render)) return;
    render();
  }

  function render(target = root) {
    if (!root) return;
    root.hidden = false;
    root.classList.remove('route-line-status', 'route-data-page', 'route-client-details-host', 'route-insights-host', 'route-insights-home', 'route-log-center-host');
    root.classList.add('route-workspace', 'policy-table-route-host', MODULE_CLASS);
    target.innerHTML = `<section class="storage-file-shell">${noticeMarkup()}<main class="storage-file-workbench">${toolbarMarkup()}${tableMarkup()}</main>${drawerMarkup()}</section>`;
    ui.mountAll?.(target);
  }

  function patchTable() {
    const current = root?.querySelector('.storage-file-table-card');
    if (!current) { render(); return; }
    const scroll = current.querySelector('.dwrt-kit-table-scroll');
    const left = scroll?.scrollLeft || 0;
    const top = scroll?.scrollTop || 0;
    const template = document.createElement('template');
    template.innerHTML = tableMarkup();
    const next = template.content.firstElementChild;
    if (!next) return;
    current.replaceWith(next);
    const nextScroll = next.querySelector('.dwrt-kit-table-scroll');
    if (nextScroll) { nextScroll.scrollLeft = left; nextScroll.scrollTop = top; }
    ui.mountAll?.(next);
    updateToolbarState();
  }

  function updateToolbarState() {
    const count = state.selected.size;
    root?.querySelectorAll('[data-file-copy],[data-file-cut],[data-file-compress],[data-file-delete-selected]').forEach((button) => { button.disabled = !count; });
    const paste = root?.querySelector('[data-file-paste]');
    if (paste) paste.disabled = !(state.clipboard?.paths?.length && hasCapability(state.clipboard.action === 'cut' ? 'move' : 'copy'));
  }

  function entryById(id) {
    return state.entries.find((entry) => entry.id === id);
  }

  function selectedEntries() {
    return state.entries.filter((entry) => state.selected.has(entry.id));
  }

  function closeDrawer() {
    state.drawer = '';
    state.editor = {};
    state.uploadFiles = [];
    state.notice = '';
    state.noticeTone = '';
    state.confirmDelete = false;
    render();
  }

  function openDrawer(type, editor = {}) {
    state.drawer = type;
    state.editor = editor;
    state.notice = '';
    state.noticeTone = '';
    state.confirmDelete = false;
    render();
  }

  function openNew() { openDrawer('new', { kind: '', name: '' }); }
  function openUpload() { state.uploadFiles = []; openDrawer('upload', { mode: 'local', url: '', name: '', nameTouched: false }); }
  function openRename(entry) { openDrawer('rename', { entry, name: entry.name }); }
  function openPermissions(entry) { openDrawer('permissions', { entry, mode: firstText(entry.mode_octal, symbolicModeToOctal(entry.mode)), owner: entry.owner, group: entry.group }); }
  function openCompress() { if (state.selected.size) openDrawer('compress', { format: 'zip', name: 'archive.zip' }); }
  function openExtract(entry) { openDrawer('extract', { entry, destination: state.path }); }
  function openDelete(entries) { if (entries.length) openDrawer('delete', { entries }); }

  async function openTextEditor(entry) {
    openDrawer('editor', { entry, name: entry.name, content: '', etag: '', loadingContent: true, contentError: '' });
    if (!hasCapability('read', entry) && !hasCapability('preview', entry)) return;
    try {
      const payload = await requestJson(`${ENDPOINT}/content?path=${encodeURIComponent(apiPath(entry.path))}${state.rootId ? `&root_id=${encodeURIComponent(state.rootId)}` : ''}`);
      if (!state.mounted || state.drawer !== 'editor' || state.editor.entry?.id !== entry.id) return;
      state.editor.content = firstText(payload.content, payload.text);
      /* 保存的前置条件就是这一次读回来的 etag，别处拿不到：列目录的 entry 不含 etag。 */
      state.editor.etag = firstText(payload.etag);
      state.editor.loadingContent = false;
      render();
    } catch (error) {
      if (!state.mounted) return;
      state.editor.loadingContent = false;
      /* 「目录能进、文件打不开」是后端有意的保护语义（列目录保留可导航性，只拒绝读字节）。
       * 把 reason 如实呈现，不要显示成加载失败或空文件。 */
      /* 原因只在抽屉里说一次；再往页面顶部推一条同文案的通知是重复噪音。 */
      state.editor.contentError = contentErrorText(error);
      render();
    }
  }

  function contentErrorText(error) {
    const message = firstText(error?.message);
    if (/protected_system_path|protected_executable_or_boot_path|protected_system_account_or_boot_file/.test(message)) {
      return '系统受保护路径，内容不予显示。该目录可以浏览，但文件内容按安全策略不下发。';
    }
    if (/protected_credential_or_database_file/.test(message)) {
      return '凭据或数据库文件，内容不予显示。密钥、证书与数据库文件按安全策略不下发。';
    }
    if (/content_protected/.test(message)) return '该文件受安全策略保护，内容不予显示。';
    /* 403 优先判状态码：后端错误串是英文且带内部风险等级名（"'medium' risk action"），
     * 不能漏给终端用户。必须排在 content_protected 之后——operator 以上读受保护路径
     * 拿到的仍是 400 content_protected，两者对用户的后续动作完全不同：
     * 这一条换个高权限账号就能看，那几条换谁都看不到。 */
    if (error?.status === 403 || /forbidden/i.test(message)) {
      return '当前账号没有查看文件内容的权限。目录可以浏览，读取内容需要更高权限的账号。';
    }
    if (/text_too_large/.test(message)) return '文件超出可在线查看的大小上限，请下载后查看。';
    if (/not_utf8_text/.test(message)) return '该文件不是 UTF-8 文本，无法在编辑器中显示。';
    if (/mount_boundary_rejected/.test(message)) return '该文件属于另一个挂载点，需要从它自己的存储根打开。';
    if (/file_read_failed|directory_unavailable/.test(message)) return '文件读取失败，可能已被删除或没有读取权限。';
    if (error?.status === 401) return '会话已过期，请重新登录后再查看。';
    return message ? `读取失败：${message}` : '读取失败。';
  }

  function openEntry(entry) {
    if (entry.is_dir) { openDirectory(entry.path); return; }
    if (entry.kind === 'text') { openTextEditor(entry); return; }
    if (['image', 'video', 'audio'].includes(entry.kind)) { openDrawer('preview', { entry, name: entry.name }); return; }
    if (entry.kind === 'package') { openDrawer('package', { entry, name: entry.name }); return; }
    downloadEntry(entry);
  }

  /* 子挂载点在当前根里列得出来，但进不去（RESOLVE_NO_XDEV）。它们各自是独立的根，
   * 所以点进这类目录时直接切到它自己的 root_id，而不是让后端回 mount_boundary_rejected。 */
  function openDirectory(path) {
    const target = displayPath(path);
    const owner = state.roots.find((item) => item.path === target);
    if (owner && owner.id !== state.rootId) { load(owner.path, false, owner.id); return; }
    load(target);
  }

  /* 写入统一走这里。三条硬约束都在这一处收口，避免各调用点各写一遍写漏：
   *   1. confirm 必须是 JSON 布尔 true，字符串 "true" 不算
   *      （storage_files_json_bool() 严格要求 json_type_boolean，:1191）；
   *   2. root_id 显式带上——省略时后端对 `/` 或空 path 会回落到 roots[0]（:433），
   *      多根机器上会静默落错根，写错根比报错危险；
   *   3. action 必须在白名单内，否则后端回 unsupported_action。 */
  async function mutate(action, fields) {
    if (!MUTATE_ACTIONS.has(action)) throw new Error(`unsupported_action: ${action}`);
    return requestJson(MUTATE_ENDPOINT, {
      method: 'POST',
      body: JSON.stringify({ action, confirm: true, root_id: state.rootId, ...fields })
    });
  }

  async function submitDrawer() {
    if (!drawerCanSave() || state.saving) return;
    if (state.drawer === 'delete' && !state.confirmDelete) { state.confirmDelete = true; render(); return; }
    state.saving = true;
    state.notice = '';
    render();
    try {
      if (state.drawer === 'new') {
        /* 父目录走 `path`，新建项名走 `name`——后端在 :1398 用
         * storage_files_join_path(display, name) 拼接，没有 `parent` 这个键。 */
        await mutate(state.editor.kind === 'directory' ? 'mkdir' : 'create', {
          path: apiPath(state.path),
          name: state.editor.name,
          ...(state.editor.kind === 'directory' ? {} : { content: '' })
        });
      } else if (state.drawer === 'rename') {
        /* 同目录改名，字段是 `new_name`；发 `name` 会被判 invalid_name。 */
        await mutate('rename', {
          path: apiPath(state.editor.entry.path),
          new_name: state.editor.name
        });
      } else if (state.drawer === 'editor') {
        /* expected_etag 只能来自读内容时返回的 etag（:1173），列表 entry 里没有这个字段；
         * 拿 modified_unix 凑必然 revision_conflict。 */
        await mutate('write', {
          path: apiPath(state.editor.entry.path),
          content: state.editor.content,
          expected_etag: state.editor.etag
        });
      } else {
        /* upload / permissions / compress / extract / delete / package 都没有后端端点。
         * 它们的保存按钮本就被 capabilities 禁用，但这里显式拒绝：一旦哪天能力位先翻真、
         * 端点还没接，落到这里会静默报「已完成」，那比报错难查得多。 */
        throw new Error('unsupported_action');
      }
      if (!state.mounted) return;
      state.saving = false;
      state.drawer = '';
      state.editor = {};
      state.uploadFiles = [];
      state.notice = '文件操作已完成';
      state.noticeTone = 'ok';
      await load(state.path, true);
    } catch (error) {
      if (!state.mounted) return;
      state.saving = false;
      state.notice = mutateErrorText(error);
      state.noticeTone = 'error';
      render();
    }
  }

  /* mutate 的失败码是有语义的，逐条译出来。尤其 revision_conflict 与 write_protected：
   * 一个要用户重新打开文件，一个是安全策略拒绝，混成「操作失败」用户无从判断。 */
  function mutateErrorText(error) {
    const message = firstText(error?.message);
    if (/revision_conflict/.test(message)) return '文件在你编辑期间已被改动，保存已取消。请关闭后重新打开该文件，确认最新内容再改。';
    if (/expected_etag_required/.test(message)) return '缺少文件版本标记，保存已取消。请关闭后重新打开该文件再试。';
    if (/write_protected/.test(message)) return '目标路径受写入保护，按安全策略不允许写入。';
    if (/storage_root_read_only/.test(message)) return '该存储根是只读的，无法写入。';
    if (/confirmation_required/.test(message)) return '该操作缺少确认标记，未执行。';
    if (/unsupported_action/.test(message)) return '当前固件不支持该操作。';
    if (/invalid_name/.test(message)) return '名称不合法：不能为空、不能含 / 或 \\、不能是 . 或 ..。';
    if (/invalid_text_content/.test(message)) return '内容必须是 UTF-8 文本，且不超过 256 KiB。';
    if (/invalid_relative_path/.test(message)) return '该路径不在当前存储根范围内。请切换到对应的存储位置。';
    if (/directory_unavailable/.test(message)) return '目标目录无法安全打开，可能已被删除或没有权限。';
    if (/filesystem_transaction_failed/.test(message)) return '文件系统事务失败，改动未提交。';
    if (/storage_root_not_found/.test(message)) return '该路径不属于任何可访问的存储根。';
    if (error?.status === 401) return '会话已过期，请重新登录后再操作。';
    if (error?.status === 403) return '当前账号没有执行该写入操作的权限。';
    if (error?.status === 404) return '后端尚未开放文件写入接口。';
    return message ? `操作失败：${message}` : '操作失败。';
  }

  async function pasteClipboard() {
    const clipboard = state.clipboard;
    if (!clipboard?.paths?.length) return;
    /* copy / move 在后端 action 白名单里不存在，端点也没有，而且跨根被架构挡住：
     * 一次 mutate 只持有一个 root，RESOLVE_NO_XDEV + st_dev 校验使跨 dev 需要双根事务模型。
     * 所以不发请求——粘贴按钮本就按 capabilities 禁用，这里只兜键盘快捷键等旁路入口。 */
    state.notice = '当前固件不支持复制/移动。';
    state.noticeTone = 'warning';
    render();
  }

  function rememberSelection(action) {
    /* 复制/剪切时就把路径转成当前根的接口形式：粘贴时当前根可能已经换了，
     * 那时再按新根拼装会指到错误的位置。 */
    const paths = selectedEntries().map((entry) => apiPath(entry.path));
    if (!paths.length) return;
    state.clipboard = { action, paths, source: state.path, sourceRootId: state.rootId };
    state.notice = action === 'cut' ? `已准备移动 ${paths.length} 个项目` : `已准备复制 ${paths.length} 个项目`;
    state.noticeTone = 'info';
    render();
  }

  function downloadEntry(entry) {
    if (!entry || !hasCapability('download', entry)) {
      state.notice = '后端下载能力尚未开放';
      state.noticeTone = 'warning';
      render();
      return;
    }
    const link = document.createElement('a');
    /*
     * 后端没有 /download 这条路由，字节流合并在 /raw 上：预览走默认的
     * Content-Disposition: inline，下载加 ?disposition=attachment，
     * 两者共用同一个处理器（jmx_app_perms.c 里注册的是 GET,HEAD /storage/files/raw）。
     * 之前这里写 /download，只是因为 download 能力位恒为 false 才没暴露成 404。
     */
    link.href = `${ENDPOINT}/raw?path=${encodeURIComponent(apiPath(entry.path))}`
      + `${state.rootId ? `&root_id=${encodeURIComponent(state.rootId)}` : ''}`
      + `&disposition=attachment&v=${VERSION}`;
    /* 后端已给出 attachment 与 filename，这里保留 download 属性只作为兜底。 */
    link.download = entry.name;
    link.click();
  }

  function onClick(event) {
    if (event.target.closest('[data-file-close]')) { closeDrawer(); return; }
    if (event.target.closest('[data-file-upload]')) { openUpload(); return; }
    if (event.target.closest('[data-file-new]')) { openNew(); return; }
    if (event.target.closest('[data-file-copy]')) { rememberSelection('copy'); return; }
    if (event.target.closest('[data-file-cut]')) { rememberSelection('cut'); return; }
    if (event.target.closest('[data-file-paste]')) { pasteClipboard(); return; }
    if (event.target.closest('[data-file-compress]')) { openCompress(); return; }
    if (event.target.closest('[data-file-delete-selected]')) { openDelete(selectedEntries()); return; }
    if (event.target.closest('[data-file-save]')) { submitDrawer(); return; }
    const path = event.target.closest('[data-file-path]');
    if (path) { openDirectory(path.dataset.filePath); return; }
    const kind = event.target.closest('[data-file-new-kind]');
    if (kind) { state.editor.kind = kind.dataset.fileNewKind; state.editor.name = ''; render(); return; }
    const open = event.target.closest('[data-file-open]');
    if (open) { const entry = entryById(open.dataset.fileOpen); if (entry) openEntry(entry); return; }
    const rename = event.target.closest('[data-file-rename]');
    if (rename) { const entry = entryById(rename.dataset.fileRename); if (entry) openRename(entry); return; }
    const permissions = event.target.closest('[data-file-permissions]');
    if (permissions) { const entry = entryById(permissions.dataset.filePermissions); if (entry) openPermissions(entry); return; }
    const remove = event.target.closest('[data-file-delete]');
    if (remove) { const entry = entryById(remove.dataset.fileDelete); if (entry) openDelete([entry]); return; }
    const download = event.target.closest('[data-file-download]');
    if (download) { downloadEntry(entryById(download.dataset.fileDownload)); return; }
    const extract = event.target.closest('[data-file-extract]');
    if (extract) { const entry = entryById(extract.dataset.fileExtract); if (entry) openExtract(entry); return; }
    const uploadMode = event.target.closest('[data-file-upload-mode]');
    if (uploadMode) { state.editor.mode = uploadMode.dataset.fileUploadMode; render(); }
  }

  function onInput(event) {
    const search = event.target.closest('[data-file-search]');
    if (search) { state.query = search.value; patchTable(); return; }
    const draft = event.target.closest('[data-file-draft]');
    if (!draft || draft.tagName === 'SELECT') return;
    state.editor[draft.dataset.fileDraft] = draft.value;
    if (state.drawer === 'upload' && state.editor.mode === 'url') {
      if (draft.dataset.fileDraft === 'name') state.editor.nameTouched = true;
      if (draft.dataset.fileDraft === 'url' && !state.editor.nameTouched) {
        try {
          const input = /^https?:\/\//i.test(draft.value) ? draft.value : `https://${draft.value}`;
          const parts = new URL(input).pathname.split('/').filter(Boolean);
          state.editor.name = decodeURIComponent(parts.pop() || '');
          const nameInput = root?.querySelector('[data-file-draft="name"]');
          if (nameInput) nameInput.value = state.editor.name;
        } catch (_) {
          state.editor.name = '';
        }
      }
    }
    const save = root?.querySelector('[data-file-save]');
    if (save) save.disabled = !drawerCanSave() || state.saving;
  }

  function onChange(event) {
    const rootSelect = event.target.closest('[data-file-root]');
    /* 切根要按 root_id 走，并回到该根的根目录；沿用旧 path 会落到别的根里。 */
    if (rootSelect) { const next = rootById(rootSelect.value); load(next?.path || '/', false, rootSelect.value); return; }
    const all = event.target.closest('[data-file-select-all]');
    if (all) {
      filteredEntries().forEach((entry) => all.checked ? state.selected.add(entry.id) : state.selected.delete(entry.id));
      patchTable();
      return;
    }
    const select = event.target.closest('[data-file-select]');
    if (select) {
      if (select.checked) state.selected.add(select.dataset.fileSelect); else state.selected.delete(select.dataset.fileSelect);
      patchTable();
      return;
    }
    const upload = event.target.closest('[data-file-upload-input]');
    if (upload) { state.uploadFiles = [...upload.files]; render(); return; }
    const draft = event.target.closest('[data-file-draft]');
    if (draft) { state.editor[draft.dataset.fileDraft] = draft.value; render(); }
  }

  function onKeyDown(event) {
    if (event.key === 'Escape' && state.drawer) closeDrawer();
  }

  /* 落点选择：后端 roots[] 按路径字典序排，`/` 恒排第一且是只读根。用户打开文件管理
   * 第一眼落在一个不能写的根上，会以为整个文件管理都是只读的。所以首屏先按默认根拿
   * roots 清单，再挑一个可写根落下去；`/data` 优先（用户数据所在），其次任意可写根，
   * 全只读时才留在默认根。偏好路径只用于排序，不硬编码根是否存在。 */
  const PREFERRED_ROOTS = ['/data', '/root', '/opt/dreamingwrt'];

  function preferredRoot() {
    const writable = state.roots.filter((item) => !item.read_only);
    if (!writable.length) return null;
    for (const path of PREFERRED_ROOTS) {
      const match = writable.find((item) => item.path === path);
      if (match) return match;
    }
    return writable[0];
  }

  async function bootstrap() {
    await load('/');
    if (!state.mounted || !state.loaded) return;
    if (!isReadOnlyRoot()) return;
    const target = preferredRoot();
    if (!target || target.id === state.rootId) return;
    await load(target.path, false, target.id);
  }

  root?.addEventListener('click', onClick);
  root?.addEventListener('input', onInput);
  root?.addEventListener('change', onChange);
  document.addEventListener('keydown', onKeyDown);
  stage?.classList.add('is-storage-files');
  render();
  bootstrap();

  /*
   * 手动刷新按钮按用户第 9 条删除，补一条可见性受控的轮询代替；
   * 抽屉打开、正在保存或有未提交草稿时跳过，避免刷掉用户填的内容。
   */
  state.pollTimer = window.setInterval(() => {
    if (!state.mounted || document.hidden) return;
    if (state.loading || state.refreshing || state.saving) return;
    if (state.drawer || state.selected.size) return;
    load(state.path, true);
  }, 20000);

  return {
    refresh() { return load(state.path, true); },
    unmount() {
      state.mounted = false;
      state.seq += 1;
      window.clearInterval(state.pollTimer);
      root?.removeEventListener('click', onClick);
      root?.removeEventListener('input', onInput);
      root?.removeEventListener('change', onChange);
      document.removeEventListener('keydown', onKeyDown);
      root?.replaceChildren();
      root?.classList.remove('route-workspace', 'policy-table-route-host', MODULE_CLASS);
      stage?.classList.remove('is-storage-files');
    }
  };
}

export default { mount };
