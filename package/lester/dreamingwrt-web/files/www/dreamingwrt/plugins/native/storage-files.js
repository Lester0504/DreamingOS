export function mount(context = {}) {
  const root = context.root || document.getElementById('routePreview');
  const api = context.api || {};
  const ui = context.ui || {};
  const utils = context.utils || {};
  const escapeHtml = utils.escapeHtml || ((value) => String(value ?? '').replace(/[&<>"']/g, (character) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[character]));
  const VERSION = '20260716-25';
  const ENDPOINT = '/api/v1/storage/files';
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
    loading: true,
    refreshing: false,
    saving: false,
    loaded: false,
    error: '',
    notice: '',
    noticeTone: '',
    path: '/',
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
    const response = await fetch(`${url}${url.includes('?') ? '&' : '?'}v=${VERSION}`, {
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
    if (typeof item === 'string') return { id: item, label: item === '/' ? '根目录' : item, path: normalizePath(item) };
    const path = normalizePath(firstText(item.path, item.mount_point, item.root, '/'));
    return { ...item, id: firstText(item.id, item.uuid, path, `root-${index + 1}`), label: firstText(item.label, item.name, path === '/' ? '根目录' : path), path };
  }

  function normalizePayload(payload = {}) {
    const source = payload.files && typeof payload.files === 'object' ? payload.files : payload;
    return {
      path: normalizePath(firstText(source.path, source.cwd, source.directory, state.path)),
      entries: asArray(source.entries, ['files', 'items']).map(normalizeEntry),
      roots: asArray(source.roots, ['volumes', 'mounts']).map(normalizeRoot),
      capabilities: source.capabilities && typeof source.capabilities === 'object' ? source.capabilities : {},
      limits: source.limits && typeof source.limits === 'object' ? source.limits : {}
    };
  }

  async function load(path = state.path, background = false) {
    const seq = ++state.seq;
    const nextPath = normalizePath(path);
    if (background) state.refreshing = true; else state.loading = true;
    state.error = '';
    render();
    try {
      const payload = normalizePayload(await requestJson(`${ENDPOINT}?path=${encodeURIComponent(nextPath)}`));
      if (!state.mounted || seq !== state.seq) return;
      state.path = payload.path;
      state.entries = payload.entries;
      state.roots = payload.roots;
      state.capabilities = payload.capabilities;
      state.limits = payload.limits;
      state.selected.clear();
      state.loaded = true;
    } catch (error) {
      if (!state.mounted || seq !== state.seq) return;
      state.path = nextPath;
      state.entries = [];
      state.error = '文件管理后端接口尚未开放。页面保留完整操作结构，但不会读取或伪造设备文件。';
    } finally {
      if (!state.mounted || seq !== state.seq) return;
      state.loading = false;
      state.refreshing = false;
      render();
    }
  }

  function hasCapability(action, entry = null) {
    const local = entry?.capabilities || {};
    return local[action] === true || state.capabilities[action] === true || state.capabilities[`file_${action}`] === true;
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

  function breadcrumbMarkup() {
    const parts = state.path.split('/').filter(Boolean);
    let current = '';
    const crumbs = [`<button type="button" data-file-path="/" aria-label="根目录">${icon('home')}<span>根目录</span></button>`];
    parts.forEach((part) => {
      current = `${current}/${part}`;
      crumbs.push(`<span>${icon('chevron')}</span><button type="button" data-file-path="${escapeHtml(current)}">${escapeHtml(part)}</button>`);
    });
    return `<nav class="storage-file-breadcrumb" aria-label="文件路径">${crumbs.join('')}</nav>`;
  }

  function rootsMarkup() {
    if (!state.roots.length) return '';
    return `<select class="storage-file-root-select" data-file-root aria-label="存储位置">${state.roots.map((item) => `<option value="${escapeHtml(item.path)}" ${state.path === item.path || state.path.startsWith(`${item.path}/`) ? 'selected' : ''}>${escapeHtml(item.label)}</option>`).join('')}</select>`;
  }

  function toolbarMarkup() {
    const count = state.selected.size;
    const canPaste = Boolean(state.clipboard?.paths?.length) && hasCapability(state.clipboard.action === 'cut' ? 'move' : 'copy');
    return `<header class="storage-file-toolbar"><div class="storage-file-toolbar-top">${rootsMarkup()}${breadcrumbMarkup()}</div><div class="policy-toolbar storage-file-actions"><label class="policy-search policy-search-main storage-file-search" data-dwrt-component="expand-search"><span class="dwrt-kit-expand-search-original-icon">${icon('search')}</span><input type="search" data-file-search value="${escapeHtml(state.query)}" placeholder="搜索文件或文件夹"></label><div class="storage-file-selection-actions"><button class="policy-filter-button" type="button" data-file-copy ${count ? '' : 'disabled'}>${icon('copy')}<span>复制</span></button><button class="policy-filter-button" type="button" data-file-cut ${count ? '' : 'disabled'}>${icon('cut')}<span>剪切</span></button><button class="policy-filter-button" type="button" data-file-paste ${canPaste ? '' : 'disabled'}>${icon('paste')}<span>粘贴</span></button><button class="policy-filter-button" type="button" data-file-compress ${count ? '' : 'disabled'}>${icon('compress')}<span>压缩</span></button><button class="policy-filter-button danger" type="button" data-file-delete-selected ${count ? '' : 'disabled'}>${icon('trash')}<span>删除</span></button></div><div class="policy-toolbar-actions"><button class="policy-filter-button" type="button" data-file-refresh ${state.refreshing ? 'disabled' : ''}>${icon('refresh')}<span>${state.refreshing ? '正在刷新' : '刷新'}</span></button><button class="policy-filter-button" type="button" data-file-upload>${icon('upload')}<span>上传</span></button><button class="policy-create-button" type="button" data-file-new>${icon('plus')}<span>新建</span></button></div></div></header>`;
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
    return `<div class="storage-file-row-actions">${entry.kind === 'archive' ? `<button type="button" data-file-extract="${escapeHtml(entry.id)}" aria-label="解压" data-dwrt-tooltip="解压">${icon('archive')}</button>` : !entry.is_dir ? `<button type="button" data-file-download="${escapeHtml(entry.id)}" aria-label="下载" data-dwrt-tooltip="下载">${icon('download')}</button>` : ''}<button type="button" data-file-rename="${escapeHtml(entry.id)}" aria-label="重命名" data-dwrt-tooltip="重命名">${icon('edit')}</button><button type="button" data-file-permissions="${escapeHtml(entry.id)}" aria-label="权限与属主" data-dwrt-tooltip="权限与属主">${icon('lock')}</button><button class="danger" type="button" data-file-delete="${escapeHtml(entry.id)}" aria-label="删除" data-dwrt-tooltip="删除">${icon('trash')}</button></div>`;
  }

  function tableMarkup() {
    const entries = filteredEntries();
    const rows = entries.map((entry) => {
      const selected = state.selected.has(entry.id);
      const target = entry.is_dir ? 'directory' : ['text', 'image', 'video', 'audio', 'package'].includes(entry.kind) ? entry.kind : 'download';
      return `<tr class="${selected ? 'is-selected' : ''}" data-file-row="${escapeHtml(entry.id)}"><td><input type="checkbox" data-file-select="${escapeHtml(entry.id)}" ${selected ? 'checked' : ''} aria-label="选择 ${escapeHtml(entry.name)}"></td><td><button class="storage-file-name" type="button" data-file-open="${escapeHtml(entry.id)}" data-file-target="${target}"><span class="is-${escapeHtml(entry.kind)}">${icon(kindIcon(entry.kind))}</span><span><strong>${escapeHtml(entry.name)}</strong>${entry.link_target ? `<small>→ ${escapeHtml(entry.link_target)}</small>` : ''}</span></button></td><td>${entry.is_dir ? '--' : formatBytes(entry.size_bytes)}</td><td>${escapeHtml(formatTime(entry))}</td><td><code>${escapeHtml(entry.mode || '--')}</code></td><td>${escapeHtml([entry.owner, entry.group].filter(Boolean).join('/') || '--')}</td><td>${rowActionMarkup(entry)}</td></tr>`;
    });
    const empty = state.loading && !state.loaded ? '正在读取目录' : state.error ? '后端文件管理能力尚未接入' : state.query ? '没有符合搜索条件的文件' : '此目录为空';
    const allSelected = entries.length > 0 && entries.every((entry) => state.selected.has(entry.id));
    return `<section class="storage-file-table-card dwrt-kit-table-wrap dwrt-kit-datatable-wrap dwrt-kit-glass-surface"><div class="dwrt-kit-table-toolbar"><div class="dwrt-kit-table-title"><strong>${escapeHtml(state.path)}</strong><span>${state.selected.size ? `已选择 ${state.selected.size} 项` : '名称、大小、修改时间、权限与属主'}</span></div><span class="dwrt-kit-table-count">${entries.length} 项</span></div><div class="dwrt-kit-table-scroll"><table class="dwrt-kit-table dwrt-kit-datatable storage-file-table"><thead><tr><th><input type="checkbox" data-file-select-all ${allSelected ? 'checked' : ''} ${entries.length ? '' : 'disabled'} aria-label="全选"></th><th>名称</th><th>大小</th><th>修改时间</th><th>权限</th><th>属主</th><th>操作</th></tr></thead><tbody>${rows.length ? rows.join('') : `<tr><td colspan="7" class="dwrt-kit-table-empty">${escapeHtml(empty)}</td></tr>`}</tbody></table></div></section>`;
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
    return `<label class="storage-file-field ${options.wide ? 'is-wide' : ''}"><span>${escapeHtml(label)}</span>${control}${options.help ? `<small>${escapeHtml(options.help)}</small>` : ''}</label>`;
  }

  function drawerTitle() {
    const map = { new: '新建', upload: '添加文件', rename: '重命名', permissions: '权限与属主', compress: '压缩', extract: '解压', delete: '删除', editor: state.editor.name || '编辑文件', preview: state.editor.name || '文件预览', package: '安装软件包' };
    return map[state.drawer] || '文件管理';
  }

  function newDrawerBody() {
    return `<div class="storage-file-choice-grid"><button type="button" data-file-new-kind="directory">${icon('folder')}<span><strong>新建文件夹</strong><small>在当前目录创建文件夹</small></span></button><button type="button" data-file-new-kind="file">${icon('file')}<span><strong>新建文件</strong><small>创建空文件后可继续编辑</small></span></button></div>${state.editor.kind ? `<div class="storage-file-form">${field(state.editor.kind === 'directory' ? '文件夹名称' : '文件名称', 'name', state.editor.name, { wide: true, placeholder: state.editor.kind === 'directory' ? '新建文件夹' : 'new-file.txt' })}</div>${!hasCapability(state.editor.kind === 'directory' ? 'mkdir' : 'create') ? '<div class="storage-file-capability">后端新建能力尚未开放。</div>' : ''}` : '<div class="storage-file-empty-hint">请选择要创建的类型</div>'}${state.notice ? noticeMarkup() : ''}`;
  }

  function uploadDrawerBody() {
    const files = state.uploadFiles;
    const max = firstNumber(state.limits.max_upload_bytes);
    const mode = state.editor.mode || 'local';
    const local = `<label class="storage-file-dropzone"><input type="file" multiple data-file-upload-input><span>${icon('upload')}</span><strong>选择要上传的文件</strong><small>上传到 ${escapeHtml(state.path)}${max ? ` · 单文件上限 ${formatBytes(max)}` : ''}</small></label><div class="storage-file-upload-list">${files.length ? files.map((file) => `<div><span>${icon('file')}</span><span><strong>${escapeHtml(file.name)}</strong><small>${formatBytes(file.size)}</small></span></div>`).join('') : '<div class="storage-file-empty-hint">尚未选择文件</div>'}</div>${!hasCapability('upload') ? '<div class="storage-file-capability">后端上传能力尚未开放。浏览器不会把文件发送到其他地址。</div>' : ''}`;
    const remote = `<div class="storage-file-form">${field('下载地址', 'url', state.editor.url, { wide: true, type: 'url', placeholder: 'https://example.com/file.bin', help: '后端必须限制协议、重定向、目标地址和下载大小，防止访问内网元数据或本机管理接口。' })}${field('保存文件名', 'name', state.editor.name, { wide: true, placeholder: 'file.bin' })}</div>${!hasCapability('download_url') ? '<div class="storage-file-capability">后端 URL 下载能力尚未开放。</div>' : ''}`;
    return `<div class="storage-file-segmented" role="group" aria-label="添加文件方式"><button type="button" class="${mode === 'local' ? 'is-active' : ''}" data-file-upload-mode="local">本地上传</button><button type="button" class="${mode === 'url' ? 'is-active' : ''}" data-file-upload-mode="url">URL 下载</button></div>${mode === 'local' ? local : remote}${state.notice ? noticeMarkup() : ''}`;
  }

  function renameDrawerBody() {
    const entry = state.editor.entry;
    return `<div class="storage-file-target"><span>${icon(kindIcon(entry?.kind))}</span><div><strong>${escapeHtml(entry?.name || '--')}</strong><small>${escapeHtml(entry?.path || state.path)}</small></div></div><div class="storage-file-form">${field('新名称', 'name', state.editor.name, { wide: true })}</div>${!hasCapability('rename', entry) ? '<div class="storage-file-capability">后端重命名能力尚未开放。</div>' : ''}${state.notice ? noticeMarkup() : ''}`;
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
    return `<div class="storage-file-editor-meta"><code>${escapeHtml(entry?.path || '')}</code><span>${formatBytes(entry?.size_bytes)}</span></div><label class="storage-file-editor"><textarea data-file-draft="content" spellcheck="false" ${state.editor.loadingContent ? 'disabled' : ''}>${escapeHtml(state.editor.content || '')}</textarea></label>${!hasCapability('write', entry) ? '<div class="storage-file-capability">后端文本写入能力尚未开放。可以查看内容，但保存按钮保持禁用。</div>' : ''}${state.notice ? noticeMarkup() : ''}`;
  }

  function previewDrawerBody() {
    const entry = state.editor.entry;
    const src = `${ENDPOINT}/content?path=${encodeURIComponent(entry?.path || '')}&v=${VERSION}`;
    if (entry?.kind === 'image') return `<div class="storage-file-media"><img src="${escapeHtml(src)}" alt="${escapeHtml(entry.name)}"></div>`;
    if (entry?.kind === 'video') return `<div class="storage-file-media"><video src="${escapeHtml(src)}" controls></video></div>`;
    if (entry?.kind === 'audio') return `<div class="storage-file-media is-audio"><span>${icon('audio')}</span><strong>${escapeHtml(entry.name)}</strong><audio src="${escapeHtml(src)}" controls></audio></div>`;
    return '<div class="storage-file-empty-hint">此文件类型不支持预览</div>';
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
    if (state.drawer === 'new') return Boolean(state.editor.kind && state.editor.name && hasCapability(state.editor.kind === 'directory' ? 'mkdir' : 'create'));
    if (state.drawer === 'upload') return state.editor.mode === 'url' ? Boolean(state.editor.url && state.editor.name && hasCapability('download_url')) : state.uploadFiles.length > 0 && hasCapability('upload');
    if (state.drawer === 'rename') return Boolean(state.editor.name && hasCapability('rename', state.editor.entry));
    if (state.drawer === 'permissions') return Boolean(state.editor.mode && hasCapability('permissions', state.editor.entry));
    if (state.drawer === 'compress') return Boolean(state.editor.name && hasCapability('compress'));
    if (state.drawer === 'extract') return Boolean(state.editor.destination && hasCapability('extract', state.editor.entry));
    if (state.drawer === 'delete') return Boolean((state.editor.entries || []).length && state.editor.entries.every((entry) => hasCapability('delete', entry)));
    if (state.drawer === 'editor') return hasCapability('write', state.editor.entry) && !state.editor.loadingContent;
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
    const readonly = state.drawer === 'preview';
    return `<button class="dwrt-kit-sheet-overlay is-open" type="button" data-file-close aria-label="关闭文件管理面板"></button><aside class="storage-file-drawer dwrt-kit-sheet dwrt-kit-glass-surface is-open" aria-label="${escapeHtml(drawerTitle())}"><header class="dwrt-kit-sheet-header"><div><span>FILE MANAGER</span><strong>${escapeHtml(drawerTitle())}</strong></div><button class="dwrt-kit-sheet-close" type="button" data-file-close aria-label="关闭">×</button></header><div class="dwrt-kit-sheet-body storage-file-drawer-body">${drawerBody()}</div><footer class="dwrt-kit-sheet-footer storage-file-drawer-footer"><span></span><div><button class="policy-secondary" type="button" data-file-close>${readonly ? '关闭' : '取消'}</button>${readonly ? '' : `<button class="policy-primary ${state.drawer === 'delete' ? 'danger' : ''}" type="button" data-file-save ${drawerCanSave() && !state.saving ? '' : 'disabled'}>${drawerSaveLabel()}</button>`}</div></footer></aside>`;
  }

  function render() {
    if (!root) return;
    root.hidden = false;
    root.classList.remove('route-line-status', 'route-data-page', 'route-client-details-host', 'route-insights-host', 'route-insights-home', 'route-log-center-host');
    root.classList.add('route-workspace', 'policy-table-route-host', MODULE_CLASS);
    root.innerHTML = `<section class="storage-file-shell">${noticeMarkup()}<main class="storage-file-workbench">${toolbarMarkup()}${tableMarkup()}</main>${drawerMarkup()}</section>`;
    ui.mountAll?.(root);
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
    openDrawer('editor', { entry, name: entry.name, content: '', loadingContent: true });
    if (!hasCapability('read', entry) && !hasCapability('preview', entry)) return;
    try {
      const payload = await requestJson(`${ENDPOINT}/content?path=${encodeURIComponent(entry.path)}`);
      if (!state.mounted || state.drawer !== 'editor' || state.editor.entry?.id !== entry.id) return;
      state.editor.content = firstText(payload.content, payload.text);
      state.editor.loadingContent = false;
      render();
    } catch (error) {
      if (!state.mounted) return;
      state.editor.loadingContent = false;
      state.notice = `读取失败：${firstText(error.message, '后端未返回内容')}`;
      state.noticeTone = 'error';
      render();
    }
  }

  function openEntry(entry) {
    if (entry.is_dir) { load(entry.path); return; }
    if (entry.kind === 'text') { openTextEditor(entry); return; }
    if (['image', 'video', 'audio'].includes(entry.kind)) { openDrawer('preview', { entry, name: entry.name }); return; }
    if (entry.kind === 'package') { openDrawer('package', { entry, name: entry.name }); return; }
    downloadEntry(entry);
  }

  async function submitDrawer() {
    if (!drawerCanSave() || state.saving) return;
    if (state.drawer === 'delete' && !state.confirmDelete) { state.confirmDelete = true; render(); return; }
    state.saving = true;
    state.notice = '';
    render();
    try {
      if (state.drawer === 'new') {
        await requestJson(`${ENDPOINT}/${state.editor.kind === 'directory' ? 'directories' : 'entries'}`, { method: 'POST', body: JSON.stringify({ parent: state.path, name: state.editor.name }) });
      } else if (state.drawer === 'upload') {
        if (state.editor.mode === 'url') {
          await requestJson(`${ENDPOINT}/download-url`, { method: 'POST', body: JSON.stringify({ url: state.editor.url, destination: joinPath(state.path, state.editor.name) }) });
        } else {
          const data = new FormData();
          data.append('path', state.path);
          state.uploadFiles.forEach((file) => data.append('files', file, file.name));
          await requestJson(`${ENDPOINT}/upload`, { method: 'POST', body: data });
        }
      } else if (state.drawer === 'rename') {
        await requestJson(`${ENDPOINT}/rename`, { method: 'POST', body: JSON.stringify({ path: state.editor.entry.path, name: state.editor.name }) });
      } else if (state.drawer === 'permissions') {
        await requestJson(`${ENDPOINT}/permissions`, { method: 'PUT', body: JSON.stringify({ path: state.editor.entry.path, mode: state.editor.mode, owner: state.editor.owner, group: state.editor.group }) });
      } else if (state.drawer === 'compress') {
        await requestJson(`${ENDPOINT}/compress`, { method: 'POST', body: JSON.stringify({ paths: selectedEntries().map((entry) => entry.path), format: state.editor.format, target: joinPath(state.path, state.editor.name) }) });
      } else if (state.drawer === 'extract') {
        await requestJson(`${ENDPOINT}/extract`, { method: 'POST', body: JSON.stringify({ path: state.editor.entry.path, destination: normalizePath(state.editor.destination) }) });
      } else if (state.drawer === 'delete') {
        await requestJson(`${ENDPOINT}/entries`, { method: 'DELETE', body: JSON.stringify({ paths: state.editor.entries.map((entry) => entry.path), confirm: true }) });
      } else if (state.drawer === 'editor') {
        await requestJson(`${ENDPOINT}/content`, { method: 'PUT', body: JSON.stringify({ path: state.editor.entry.path, content: state.editor.content, expected_mtime: state.editor.entry.modified_unix || state.editor.entry.modified_at }) });
      } else if (state.drawer === 'package') {
        await requestJson(`${ENDPOINT}/install-package`, { method: 'POST', body: JSON.stringify({ path: state.editor.entry.path, confirm: true }) });
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
      state.notice = `操作失败：${firstText(error.message, '后端未接受操作')}`;
      state.noticeTone = 'error';
      render();
    }
  }

  async function pasteClipboard() {
    const clipboard = state.clipboard;
    if (!clipboard?.paths?.length) return;
    const action = clipboard.action === 'cut' ? 'move' : 'copy';
    if (!hasCapability(action)) return;
    try {
      await requestJson(`${ENDPOINT}/${action}`, { method: 'POST', body: JSON.stringify({ paths: clipboard.paths, destination: state.path }) });
      if (clipboard.action === 'cut') state.clipboard = null;
      state.notice = '粘贴操作已完成';
      state.noticeTone = 'ok';
      await load(state.path, true);
    } catch (error) {
      state.notice = `粘贴失败：${firstText(error.message)}`;
      state.noticeTone = 'error';
      render();
    }
  }

  function rememberSelection(action) {
    const paths = selectedEntries().map((entry) => entry.path);
    if (!paths.length) return;
    state.clipboard = { action, paths, source: state.path };
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
    link.href = `${ENDPOINT}/download?path=${encodeURIComponent(entry.path)}&v=${VERSION}`;
    link.download = entry.name;
    link.click();
  }

  function onClick(event) {
    if (event.target.closest('[data-file-close]')) { closeDrawer(); return; }
    if (event.target.closest('[data-file-refresh]')) { load(state.path, true); return; }
    if (event.target.closest('[data-file-upload]')) { openUpload(); return; }
    if (event.target.closest('[data-file-new]')) { openNew(); return; }
    if (event.target.closest('[data-file-copy]')) { rememberSelection('copy'); return; }
    if (event.target.closest('[data-file-cut]')) { rememberSelection('cut'); return; }
    if (event.target.closest('[data-file-paste]')) { pasteClipboard(); return; }
    if (event.target.closest('[data-file-compress]')) { openCompress(); return; }
    if (event.target.closest('[data-file-delete-selected]')) { openDelete(selectedEntries()); return; }
    if (event.target.closest('[data-file-save]')) { submitDrawer(); return; }
    const path = event.target.closest('[data-file-path]');
    if (path) { load(path.dataset.filePath); return; }
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
    if (rootSelect) { load(rootSelect.value); return; }
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

  root?.addEventListener('click', onClick);
  root?.addEventListener('input', onInput);
  root?.addEventListener('change', onChange);
  document.addEventListener('keydown', onKeyDown);
  stage?.classList.add('is-storage-files');
  render();
  load('/');

  return {
    refresh() { return load(state.path, true); },
    unmount() {
      state.mounted = false;
      state.seq += 1;
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
