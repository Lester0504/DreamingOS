(() => {
  'use strict';

  const API = '/api/v1/storage/files';
  const $ = (selector) => document.querySelector(selector);
  const app = $('#fmApp');
  const content = $('#fmContent');
  const kit = window.DWRT_UI_KIT;
  const escape = (value) => String(value ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const glyph = (name) => `<i data-lucide="${name}" aria-hidden="true"></i>`;
  const button = (action, label, icon, disabled = false) => `<button type="button" class="dwrt-kit-button" data-action="${action}" ${disabled ? 'disabled' : ''}>${glyph(icon)}<span>${escape(label)}</span></button>`;
  const pathName = (path) => String(path || '/').replace(/\/+/g, '/').replace(/\/$/, '') || '/';
  const parentPath = (path) => pathName(path).split('/').slice(0, -1).join('/') || '/';
  const rootLabel = (root) => root?.path === '/' ? '根文件系统' : root?.label || root?.path || '文件位置';
  const treeKey = (rootId, path) => `${rootId}:${pathName(path)}`;
  const state = {
    roots: [], rootId: '', path: '/', entries: [], capabilities: {}, limits: {},
    loading: false, error: '', target: null, sequence: 0, controller: null,
    selected: new Set(), anchor: '', history: [], historyIndex: -1,
    query: '', searchResults: null, searchLimited: false, searchPending: false, truncated: false,
    view: 'list', sort: 'name', direction: 1, hidden: false,
    tree: new Map(), clipboard: null, sheet: null, storageTools: [], activeTool: '',
    role: '', confirming: false, sessionRequired: false
  };

  function paintIcons() {
    window.lucide?.createIcons({ attrs: { 'stroke-width': 1.7, 'aria-hidden': 'true' } });
  }
  function bytes(value) {
    if (!Number.isFinite(value)) return '--';
    if (value === 0) return '0 B';
    const unit = Math.min(4, Math.floor(Math.log(Math.max(1, value)) / Math.log(1024)));
    return `${(value / 1024 ** unit).toLocaleString('zh-CN', { maximumFractionDigits: unit ? 1 : 0 })} ${['B', 'KB', 'MB', 'GB', 'TB'][unit]}`;
  }
  function time(entry) {
    if (!entry.modified_unix) return '--';
    return new Date(entry.modified_unix * 1000).toLocaleString('zh-CN', { year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', hour12: false });
  }
  function kind(entry) {
    if (entry.is_symlink) return 'symlink';
    if (entry.is_dir) return 'directory';
    if (entry.kind === 'text') return 'text';
    const name = entry.name.toLowerCase();
    if (/\.(png|jpe?g|gif|webp|avif|bmp)$/.test(name)) return 'image';
    if (/\.(mp4|webm|ogv|mov)$/.test(name)) return 'video';
    if (/\.(mp3|wav|ogg|flac|m4a|aac)$/.test(name)) return 'audio';
    if (/\.pdf$/.test(name)) return 'pdf';
    if (/\.(zip|gz|xz|tar|7z|rar)$/.test(name)) return 'archive';
    return 'file';
  }
  const kindLabels = { directory: '文件夹', symlink: '符号链接', text: '文本文件', image: '图片', video: '视频', audio: '音频', pdf: 'PDF 文档', archive: '压缩文件', file: '文件' };
  function fileIcon(entry) {
    const type = kind(entry);
    return `<span class="fm-file-icon" data-kind="${type}">${type === 'directory'
      ? '<img src="/static/desktop/assets/file-manager.png" alt="" draggable="false">'
      : glyph({ image: 'file-image', video: 'file-video', audio: 'file-audio', text: 'file-text', archive: 'file-archive', symlink: 'file-symlink', pdf: 'file-text' }[type] || 'file')}</span>`;
  }
  function apiPath(path) { return pathName(path); }
  function url(suffix = '', values = {}) {
    return `${API}${suffix}?${new URLSearchParams(values)}`;
  }
  function errorText(error) {
    if (error.status === 401) return '会话已过期，请重新登录。';
    if (error.status === 403) return '当前账号没有此操作权限。';
    const messages = {
      mount_boundary_rejected: '此目录属于另一个挂载点，请在文件位置中选择对应存储空间。',
      invalid_relative_path: '路径不在当前存储空间内。',
      directory_unavailable: '目录无法打开，可能已移除或没有访问权限。',
      storage_root_not_found: '存储空间已移除，请刷新文件位置。',
      storage_root_read_only: '此存储空间为只读。',
      content_protected: '该文件受保护，不能读取内容。',
      text_too_large: '文本超过 256 KB，无法在此编辑。',
      not_utf8_text: '该文件不是 UTF-8 文本。',
      file_changed: '文件已被其他操作修改，请重新打开后编辑。',
      revision_conflict: '文件已被其他操作修改，请重新打开后编辑。',
      file_exists: '目标文件已存在。',
      target_exists: '目标已存在，请选择冲突处理方式。',
      target_within_source: '不能将文件夹放入自身或子文件夹。',
      write_protected: '该路径受保护，不能修改。',
      capability_unavailable: '当前设备未开放此操作。'
    };
    return messages[error.code] || error.message || '操作失败，请重试。';
  }
  const request = (...args) => window.DWRT_FILES.request(...args);
  const post = (suffix, body) => request(suffix, {}, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
  function canWrite() { return ['admin', 'owner'].includes(state.role); }
  function capability(action, entry = null) {
    if (state.loading || state.error) return false;
    const caps = entry ? entry.capabilities : state.capabilities;
    if (caps?.[action] !== true) return false;
    if (action === 'list') return true;
    if (action === 'rename' && entry?.is_symlink) return false;
    return canWrite();
  }
  function selectedEntries() {
    return (state.searchResults || state.entries).filter((entry) => state.selected.has(entry.path));
  }
  function notice(text, error = false) {
    const node = $('#fmNotice');
    node.textContent = text;
    node.hidden = !text;
    node.classList.toggle('is-error', error);
  }
  function visibleEntries() {
    const rows = (state.searchResults || state.entries).filter((entry) => (state.hidden || !entry.name.startsWith('.')) &&
      (state.searchResults || !state.query || entry.name.toLocaleLowerCase().includes(state.query.toLocaleLowerCase())));
    return rows.slice().sort((a, b) => {
      if (a.is_dir !== b.is_dir) return a.is_dir ? -1 : 1;
      const left = state.sort === 'kind' ? kindLabels[kind(a)] : a[state.sort];
      const right = state.sort === 'kind' ? kindLabels[kind(b)] : b[state.sort];
      const diff = typeof left === 'number' ? left - right : String(left || '').localeCompare(String(right || ''), 'zh-CN', { numeric: true });
      return state.direction * diff;
    });
  }
  function updateControls() {
    const selected = selectedEntries();
    const enabled = {
      back: state.historyIndex > 0, forward: state.historyIndex < state.history.length - 1,
      up: state.path !== pathName(state.roots.find((r) => r.id === state.rootId)?.path),
      mkdir: capability('mkdir'), upload: capability('upload'),
      download: selected.length === 1 && !selected[0].is_dir && capability('download', selected[0]),
      delete: selected.length > 0 && selected.every((entry) => capability('delete', entry))
    };
    Object.entries(enabled).forEach(([action, value]) => {
      document.querySelectorAll(`[data-action="${action}"]`).forEach((node) => { node.disabled = !value || state.loading; });
    });
    ['mkdir', 'upload'].forEach((action) => {
      const node = $(`.fm-commands [data-action="${action}"]`);
      node.title = !canWrite() ? '当前账号为只读' : !state.capabilities[action] ? '当前存储空间未开放此操作' : '';
    });
    const recursive = $('#fmSearchScope option[value="recursive"]');
    const recursiveAvailable = canWrite() && state.capabilities.search === true;
    if (recursiveAvailable && !recursive) $('#fmSearchScope').add(new Option('含子文件夹', 'recursive'));
    if (!recursiveAvailable && recursive) { recursive.remove(); $('#fmSearchScope').value = 'current'; }
    $('#fmClipboard').textContent = state.clipboard ? `${state.clipboard.action === 'move' ? '待移动' : '待复制'} ${state.clipboard.entries.length} 项` : '';
    document.querySelectorAll('.fm-views button').forEach((node) => {
      const active = node.dataset.action === state.view;
      node.classList.toggle('is-active', active);
      node.setAttribute('aria-pressed', String(active));
    });
    const hiddenButton = $('[data-action="hidden"]');
    hiddenButton.setAttribute('aria-pressed', String(state.hidden));
    hiddenButton.title = hiddenButton.ariaLabel = state.hidden ? '隐藏隐藏文件' : '显示隐藏文件';
  }
  function renderPaths() {
    const root = state.roots.find((item) => item.id === state.rootId);
    const rootPath = pathName(root?.path);
    const relative = state.path === rootPath ? '' : state.path.slice(rootPath === '/' ? 1 : rootPath.length + 1);
    let path = rootPath;
    $('#fmBreadcrumbs').innerHTML = `<button type="button" class="fm-crumb" data-path="${escape(rootPath)}">${glyph('hard-drive')}<span>${escape(rootLabel(root))}</span></button>` +
      relative.split('/').filter(Boolean).map((part) => {
        path = pathName(`${path}/${part}`);
        return `${glyph('chevron-right')}<button type="button" class="fm-crumb" data-path="${escape(path)}" title="${escape(part)}">${escape(part)}</button>`;
      }).join('');
    const total = root?.total_bytes;
    const available = root?.available_bytes;
    $('#fmVolume').innerHTML = root ? `<div class="fm-volume-label"><span>${escape(rootLabel(root))}</span>${root.read_only ? glyph('lock-keyhole') : ''}</div>` +
      (Number.isFinite(total) && total > 0 && Number.isFinite(available) ? `<progress class="fm-volume-meter" max="${total}" value="${Math.max(0, total - available)}" aria-label="已用容量"></progress><span>${bytes(available)} 可用 / ${bytes(total)}</span>` : `<span>${escape(root.fstype || '')}${root.read_only ? ' · 只读' : ''}</span>`) : '';
    paintIcons();
  }
  function treeMarkup(root, path, name, depth = 0) {
    const key = treeKey(root.id, path);
    const node = state.tree.get(key);
    const open = node?.open;
    const active = !state.activeTool && state.rootId === root.id && state.path === pathName(path);
    const children = open ? `<div class="fm-tree-children">${node.loading ? '<span class="fm-tree-message">读取中...</span>' : node.error
      ? `<button type="button" class="fm-tree-message" data-tree="${escape(key)}">${escape(node.error)}</button>`
      : node.entries?.length ? node.entries.map((entry) => treeMarkup(root, entry.path, entry.name, depth + 1)).join('')
        : '<span class="fm-tree-message">无子文件夹</span>'}</div>` : '';
    return `<div class="fm-root-item ${active ? 'is-active' : ''}"><div class="fm-tree-row" style="--fm-depth:${Math.min(depth, 8)}">
      <button type="button" class="fm-tree-toggle" data-tree="${escape(key)}" data-root="${escape(root.id)}" data-tree-path="${escape(path)}" aria-label="${open ? '折叠' : '展开'} ${escape(name)}" aria-expanded="${!!open}">${glyph(open ? 'chevron-down' : 'chevron-right')}</button>
      <button type="button" class="fm-location-button" data-root="${escape(root.id)}" data-path="${escape(path)}" title="${escape(pathName(path))}" ${active ? 'aria-current="page"' : ''}>${glyph(depth ? 'folder' : root.path === '/' ? 'server' : 'hard-drive')}<span>${escape(name)}</span>${!depth && root.read_only ? glyph('lock-keyhole') : ''}</button>
      </div>${children}</div>`;
  }
  function renderSidebar() {
    $('#fmRoots').innerHTML = state.roots.map((root) => treeMarkup(root, root.path, rootLabel(root))).join('') ||
      '<span class="fm-tree-message">暂无存储位置</span>';
    $('#fmStorageTools').innerHTML = state.storageTools.map((tool, i) =>
      `<button type="button" class="fm-storage-tool ${state.activeTool === tool.route ? 'is-active' : ''}" data-tool="${i}">${glyph('settings-2')}<span>${escape(tool.label)}</span></button>`).join('');
    paintIcons();
  }
  async function toggleTree(buttonNode) {
    const key = buttonNode.dataset.tree;
    let node = state.tree.get(key);
    if (node?.open && !node.error) { node.open = false; renderSidebar(); return; }
    const rootId = buttonNode.dataset.root || node.rootId;
    const path = buttonNode.dataset.treePath || node.path;
    if (!node) { node = { rootId, path, entries: null }; state.tree.set(key, node); }
    node.open = true;
    if (node.entries && !node.error) { renderSidebar(); return; }
    node.loading = true;
    node.error = '';
    renderSidebar();
    try {
      const data = await request('', { root_id: rootId, path: apiPath(path, rootId) });
      node.entries = data.entries.filter((entry) => entry.is_dir && entry.capabilities?.list !== false);
    } catch (error) { node.error = errorText(error); }
    node.loading = false;
    renderSidebar();
  }
  function renderContent() {
    const scrollTop = content.scrollTop, scrollLeft = content.scrollLeft;
    if (state.loading || state.error) {
      content.innerHTML = `<div class="fm-empty">${glyph(state.error ? 'folder-x' : 'loader-circle')}<strong>${state.error ? '无法读取文件' : '正在读取文件'}</strong>${state.error ? `<p>${escape(state.error)}</p>${state.sessionRequired ? button('login', '重新登录', 'log-in') : button('retry', '重试', 'refresh-cw')}` : ''}</div>`;
    } else {
      const entries = visibleEntries();
      if (!entries.length) {
        content.innerHTML = `<div class="fm-empty">${glyph(state.query ? 'search-x' : 'folder-open')}<strong>${!state.roots.length ? '没有可访问的存储空间' : state.query ? '没有匹配的文件' : '此文件夹为空'}</strong></div>`;
      } else if (state.view === 'grid') {
        content.innerHTML = `<div class="fm-grid">${entries.map((entry) => `<div class="fm-entry fm-tile" data-entry="${escape(entry.path)}" tabindex="0" role="group" aria-label="${escape(entry.name)}"><input class="fm-check" type="checkbox" aria-label="选择 ${escape(entry.name)}">${fileIcon(entry)}<button type="button" class="fm-name-button" data-open="${escape(entry.path)}" title="${escape(entry.name)}">${escape(entry.name)}</button><span class="fm-cell-muted">${entry.is_dir ? '文件夹' : bytes(entry.size_bytes)}</span></div>`).join('')}</div>`;
      } else {
        const columns = [['name', '文件名'], ['modified_unix', '修改时间'], ['kind', '类型'], ['size_bytes', '大小']];
        content.innerHTML = `<table class="fm-table"><colgroup><col style="width:36px"><col><col style="width:150px"><col style="width:92px"><col style="width:88px"><col style="width:110px"><col style="width:120px"><col style="width:36px"></colgroup><thead><tr><th><input id="fmSelectAll" type="checkbox" aria-label="全选"></th>${columns.map(([key, label]) => `<th aria-sort="${state.sort === key ? state.direction === 1 ? 'ascending' : 'descending' : 'none'}"><button type="button" data-sort="${key}">${label}${state.sort === key ? glyph(state.direction === 1 ? 'chevron-up' : 'chevron-down') : ''}</button></th>`).join('')}<th>权限</th><th>所有者 / 组</th><th></th></tr></thead><tbody>${entries.map((entry) => `<tr class="fm-entry" data-entry="${escape(entry.path)}" tabindex="0" aria-selected="false"><td><input class="fm-check" type="checkbox" aria-label="选择 ${escape(entry.name)}"></td><td><div class="fm-name-cell">${fileIcon(entry)}<button type="button" class="fm-name-button" data-open="${escape(entry.path)}" title="${escape(entry.name)}">${escape(entry.name)}</button></div>${state.searchResults ? `<span class="fm-result-path">${escape(pathName(entry.path))}</span>` : ''}</td><td class="fm-cell-muted">${time(entry)}</td><td class="fm-cell-muted">${kindLabels[kind(entry)]}</td><td class="fm-size">${entry.is_dir ? '--' : bytes(entry.size_bytes)}</td><td class="fm-cell-muted">${escape(entry.mode || '--')}</td><td class="fm-cell-muted">${escape(entry.owner || '--')} / ${escape(entry.group || '--')}</td><td><button type="button" class="dwrt-kit-button fm-icon-button" data-entry-menu="${escape(entry.path)}" aria-label="${escape(entry.name)} 的操作" title="更多操作">${glyph('ellipsis')}</button></td></tr>`).join('')}</tbody></table>`;
      }
    }
    content.scrollTop = scrollTop;
    content.scrollLeft = scrollLeft;
    content.setAttribute('aria-busy', String(state.loading));
    updateSelection();
    updateControls();
    paintIcons();
  }
  function updateSelection() {
    const entries = visibleEntries();
    content.querySelectorAll('[data-entry]').forEach((node) => {
      const selected = state.selected.has(node.dataset.entry);
      node.classList.toggle('is-selected', selected);
      node.classList.toggle('is-cut', state.clipboard?.action === 'move' && state.clipboard.rootId === state.rootId && state.clipboard.entries.some((entry) => entry.path === node.dataset.entry));
      node.setAttribute('aria-selected', String(selected));
      const checkbox = node.querySelector('.fm-check');
      if (checkbox) checkbox.checked = selected;
    });
    const all = $('#fmSelectAll');
    if (all) {
      all.checked = !!entries.length && entries.every((entry) => state.selected.has(entry.path));
      all.indeterminate = state.selected.size > 0 && !all.checked;
    }
    $('#fmCount').textContent = state.loading ? '正在读取...' : state.error ? '读取失败' : `${entries.length} 项${state.selected.size ? ` · 已选 ${state.selected.size} 项` : ''}${state.searchLimited || state.truncated ? ' · 结果已达上限' : ''}`;
    updateControls();
  }
  async function navigate(path, rootId = state.rootId, options = {}) {
    const sequence = ++state.sequence;
    state.controller?.abort();
    state.controller = new AbortController();
    const normalized = pathName(path);
    state.target = { path: normalized, rootId };
    state.loading = true;
    state.error = '';
    state.searchResults = null;
    state.searchPending = false;
    state.searchLimited = false;
    state.selected.clear();
    state.query = '';
    $('#fmSearch').value = '';
    closeMenu();
    showFiles();
    renderContent();
    try {
      const data = await request('', { path: apiPath(normalized, rootId), ...(rootId ? { root_id: rootId } : {}) }, { signal: state.controller.signal });
      if (sequence !== state.sequence) return;
      if (!Array.isArray(data.entries) || !Array.isArray(data.roots)) throw new Error('目录响应不完整');
      state.roots = data.roots;
      state.rootId = data.root_id;
      state.path = pathName(data.path);
      state.entries = data.entries;
      state.capabilities = data.capabilities || {};
      state.limits = data.limits || {};
      state.truncated = data.entries_truncated === true;
      const location = { path: state.path, rootId: state.rootId };
      if (options.historyIndex !== undefined) state.historyIndex = options.historyIndex;
      else if (!options.refresh && (state.history[state.historyIndex]?.path !== location.path || state.history[state.historyIndex]?.rootId !== location.rootId)) {
        state.history = state.history.slice(0, state.historyIndex + 1);
        state.history.push(location);
        state.historyIndex = state.history.length - 1;
      }
      const node = state.tree.get(treeKey(state.rootId, state.path));
      if (node) { node.entries = data.entries.filter((entry) => entry.is_dir && entry.capabilities?.list !== false); node.error = ''; }
      content.scrollTop = 0;
      notice('');
    } catch (error) {
      if (sequence !== state.sequence || error.name === 'AbortError') return;
      state.error = errorText(error);
      state.sessionRequired = error.status === 401;
    } finally {
      if (sequence === state.sequence) {
        state.loading = false;
        renderPaths();
        renderSidebar();
        renderContent();
      }
    }
  }
  async function search() {
    state.query = $('#fmSearch').value.trim();
    state.selected.clear();
    if ($('#fmSearchScope').value !== 'recursive' || !state.query) { state.searchResults = null; renderContent(); return; }
    if (!capability('search')) return;
    const sequence = ++state.sequence;
    state.controller?.abort();
    state.controller = new AbortController();
    state.loading = true;
    state.searchPending = true;
    state.error = '';
    renderContent();
    try {
      const data = await request('/search', { root_id: state.rootId, path: apiPath(state.path), query: state.query, limit: 1000 }, { signal: state.controller.signal });
      if (sequence !== state.sequence) return;
      state.searchResults = data.files;
      state.searchLimited = data.limited === true;
    } catch (error) {
      if (sequence === state.sequence && error.name !== 'AbortError') state.error = errorText(error);
    } finally {
      if (sequence === state.sequence) { state.loading = false; state.searchPending = false; renderContent(); }
    }
  }
  function selectEntry(path, event = {}) {
    const rows = visibleEntries();
    if (event.shiftKey && state.anchor) {
      const start = rows.findIndex((entry) => entry.path === state.anchor);
      const end = rows.findIndex((entry) => entry.path === path);
      if (!event.metaKey && !event.ctrlKey) state.selected.clear();
      if (start >= 0 && end >= 0) rows.slice(Math.min(start, end), Math.max(start, end) + 1).forEach((entry) => state.selected.add(entry.path));
    } else {
      const toggle = event.metaKey || event.ctrlKey || event.target?.matches('.fm-check');
      if (!toggle) state.selected.clear();
      if (toggle && state.selected.has(path)) state.selected.delete(path); else state.selected.add(path);
      state.anchor = path;
    }
    updateSelection();
  }
  function findEntry(path) { return (state.searchResults || state.entries).find((entry) => entry.path === path); }
  async function openEntry(entry) {
    if (!entry || state.loading) return;
    if (entry.is_dir) {
      const otherRoot = state.roots.find((root) => pathName(root.path) === pathName(entry.path));
      return navigate(entry.path, otherRoot?.id || state.rootId);
    }
    try {
      if (!entry.capabilities) {
        const listing = await request('', { root_id: state.rootId, path: apiPath(parentPath(entry.path)) });
        entry = listing.entries.find((item) => pathName(item.path) === pathName(entry.path)) || entry;
      }
      if (capability('read', entry)) return window.DWRT_FILES.open('text-editor', { ...entry, root_id: state.rootId });
      if (capability('preview', entry)) {
        const type = kind(entry);
        if (['image', 'video', 'audio'].includes(type)) return window.DWRT_FILES.open(type === 'image' ? 'image-viewer' : 'media-player', { ...entry, root_id: state.rootId });
        if (type === 'pdf') return openPreview(entry);
      }
      if (capability('download', entry)) return download(entry);
      return openProperties(entry);
    } catch (error) { notice(errorText(error), true); }
  }
  function menuItems() {
    const entries = selectedEntries(), one = entries.length === 1 ? entries[0] : null;
    return [
      ['open', '打开', 'folder-open', !!one],
      ['rename', '重命名', 'square-pen', !!one && capability('rename', one)],
      ['copy', '复制', 'copy', !!entries.length && entries.every((entry) => capability('copy', entry))],
      ['cut', '剪切', 'scissors', !!entries.length && entries.every((entry) => capability('move', entry))],
      ['paste', '粘贴', 'clipboard-paste', !!state.clipboard && capability(state.clipboard.action)],
      ['download', '下载', 'download', !!one && !one.is_dir && capability('download', one)],
      ['create', '新建文本文件', 'file-plus', capability('create')],
      ['delete', '删除', 'trash-2', !!entries.length && entries.every((entry) => capability('delete', entry))],
      ['properties', '属性', 'info', !!one]
    ];
  }
  function showMenu(x, y) {
    const menu = $('#fmMenu');
    menu.innerHTML = menuItems().map(([action, label, icon, enabled]) => button(action, label, icon, !enabled).replace('<button ', '<button role="menuitem" ')).join('');
    menu.hidden = false;
    paintIcons();
    menu.style.left = `${Math.max(4, Math.min(x, innerWidth - menu.offsetWidth - 4))}px`;
    menu.style.top = `${Math.max(4, Math.min(y, innerHeight - menu.offsetHeight - 4))}px`;
    menu.querySelector('button:not(:disabled)')?.focus();
  }
  function closeMenu() { $('#fmMenu').hidden = true; }

  function field(label, name, value = '', attrs = '') {
    return `<label class="fm-field"><span>${escape(label)}</span><input class="dwrt-kit-input" name="${name}" value="${escape(value)}" ${attrs}></label>`;
  }
  function targetList(entries) {
    return `<ul class="fm-target-list">${entries.map((entry) => `<li class="fm-target-item">${fileIcon(entry)}<span>${escape(entry.name)}</span></li>`).join('')}</ul>`;
  }
  function destroySheet() {
    const sheet = state.sheet;
    if (!sheet) return;
    sheet.controller?.abort();
    sheet.objectUrls?.forEach((objectUrl) => URL.revokeObjectURL(objectUrl));
    kit?.unmount($('#fmSheetHost'));
    $('#fmSheetHost').replaceChildren();
    state.sheet = null;
    sheet.trigger?.isConnected && sheet.trigger.focus({ preventScroll: true });
  }
  async function confirmDiscard() {
    if (state.confirming) return false;
    state.confirming = true;
    const host = $('#fmConfirmHost');
    host.innerHTML = kit.confirmationMarkup({ title: '放弃未保存的更改？', description: '当前编辑内容和未完成的文件操作将不再保留。', confirmLabel: '放弃更改', cancelLabel: '继续编辑', icon: glyph('triangle-alert') });
    kit.mountAll(host);
    paintIcons();
    return new Promise((resolve) => {
      const finish = (value) => {
        host.removeEventListener('click', onClick);
        kit.unmount(host);
        host.replaceChildren();
        state.confirming = false;
        resolve(value);
      };
      const onClick = (event) => {
        if (event.target.closest('[data-dwrt-confirm-accept]')) finish(true);
        else if (event.target.closest('[data-dwrt-confirm-cancel]')) finish(false);
      };
      host.addEventListener('click', onClick);
    });
  }
  async function closeSheet() {
    if (state.sheet?.busy) return;
    if (state.sheet?.dirty && !await confirmDiscard()) return;
    if (state.sheet?.type === 'upload') {
      const sheet = state.sheet;
      try {
        sheetBusy(true);
        for (const job of sheet.jobs.filter((job) => job.initialized && !job.done))
          await post('/upload/cancel', { root_id: sheet.rootId, upload_id: job.id });
      } catch (error) { sheetError(errorText(error)); sheetBusy(false); return; }
    }
    destroySheet();
  }
  function createSheet(type, title, body, footer = '') {
    if (state.sheet) return null;
    const sheet = { type, dirty: false, busy: false, rootId: state.rootId, path: state.path, trigger: document.activeElement, objectUrls: [] };
    state.sheet = sheet;
    const host = $('#fmSheetHost');
    host.innerHTML = `<button type="button" class="dwrt-kit-sheet-overlay is-open" data-fm-close aria-label="关闭文件面板"></button><aside class="dwrt-kit-sheet fm-sheet is-open" data-dwrt-component="sheet" data-dwrt-sheet-size="standard" aria-label="${escape(title)}"><header class="dwrt-kit-sheet-header"><strong>${escape(title)}</strong><button type="button" class="dwrt-kit-sheet-close" data-fm-close aria-label="关闭" title="关闭">${glyph('x')}</button></header><div class="dwrt-kit-sheet-body"><form class="fm-sheet-form">${body}<p class="fm-sheet-error" role="alert" hidden></p></form></div><footer class="dwrt-kit-sheet-footer fm-sheet-actions">${footer}</footer></aside>`;
    kit.mountAll(host);
    sheet.element = document.querySelector('.fm-sheet');
    sheet.form = sheet.element.querySelector('form');
    sheet.form.addEventListener('submit', (event) => { event.preventDefault(); submitSheet(); });
    sheet.form.addEventListener('input', () => { sheet.dirty = true; });
    paintIcons();
    return sheet;
  }
  function sheetError(text) {
    const node = state.sheet?.element.querySelector('.fm-sheet-error');
    if (node) { node.textContent = text; node.hidden = !text; }
  }
  function sheetBusy(busy) {
    if (!state.sheet) return;
    state.sheet.busy = busy;
    state.sheet.element.querySelectorAll('[data-fm-submit], [data-fm-close], input:not([type="checkbox"]), select').forEach((node) => { node.disabled = busy; });
  }
  const commandFooter = (label, icon = 'check') => `<button type="button" class="dwrt-kit-button" data-fm-close>取消</button><button type="button" class="dwrt-kit-button is-primary" data-fm-submit>${glyph(icon)}<span>${label}</span></button>`;
  function openCommand(type) {
    const entries = selectedEntries();
    const single = entries[0];
    if (['mkdir', 'create'].includes(type) && !capability(type)) return;
    if (type === 'rename' && (entries.length !== 1 || !capability('rename', single))) return;
    if (type === 'delete' && (!entries.length || !entries.every((entry) => capability('delete', entry)))) return;
    const names = { mkdir: '新建文件夹', create: '新建文本文件', rename: '重命名', delete: '删除文件' };
    const body = type === 'delete'
      ? `${targetList(entries)}<p>将永久删除这 ${entries.length} 项及文件夹内的内容，无法撤销。</p><label class="fm-field fm-confirm-delete"><input type="checkbox" name="confirmed">确认永久删除</label>`
      : `${field('名称', 'name', type === 'rename' ? single.name : '', 'required autocomplete="off" autofocus')}<span class="fm-cell-muted">${escape(state.path)}</span>`;
    const sheet = createSheet(type, names[type], body, commandFooter(type === 'delete' ? '永久删除' : type === 'rename' ? '重命名' : '创建', type === 'delete' ? 'trash-2' : 'check'));
    if (sheet) sheet.entries = entries;
  }
  function remember(action) {
    const entries = selectedEntries();
    if (!entries.length || !entries.every((entry) => capability(action, entry))) return;
    state.clipboard = { action, rootId: state.rootId, entries: entries.map((entry) => ({ ...entry, path: apiPath(entry.path) })) };
    updateSelection();
  }
  function openPaste() {
    const clip = state.clipboard;
    if (!clip || !capability(clip.action)) return;
    const sheet = createSheet('paste', clip.action === 'move' ? '移动到此处' : '复制到此处', `${targetList(clip.entries)}<div class="fm-field"><span>目标目录</span><strong>${escape(state.path)}</strong></div><label class="fm-field"><span>文件重名时</span><select class="dwrt-kit-input" name="on_conflict"><option value="">停止该项并报告</option><option value="rename">保留两者</option><option value="skip">跳过</option><option value="overwrite">覆盖目标</option></select></label>`, commandFooter(clip.action === 'move' ? '移动' : '复制'));
    if (sheet) { sheet.clip = { ...clip, entries: [...clip.entries] }; sheet.entries = [...clip.entries]; }
  }
  async function mutate(action, fields, rootId = state.rootId) {
    if (!canWrite()) throw Object.assign(new Error('只读账号不能修改文件'), { status: 403 });
    return post('/mutate', { action, root_id: rootId, confirm: true, ...fields });
  }
  function validName(value) {
    return value && value !== '.' && value !== '..' && !/[/\\\u0000-\u001f\u007f]/.test(value) &&
      !value.startsWith('.dreamingwrt-tx-') && new TextEncoder().encode(value).length <= 255;
  }
  async function submitSheet() {
    const sheet = state.sheet;
    if (!sheet || sheet.busy || sheet.partial) return;
    const form = new FormData(sheet.form);
    const name = String(form.get('name') || '');
    if (['mkdir', 'create', 'rename'].includes(sheet.type) && !validName(name)) { sheetError('请输入有效名称，不得包含斜杠、控制字符或超过 255 字节。'); return; }
    if (sheet.type === 'delete' && !form.get('confirmed')) { sheetError('请勾选确认永久删除。'); return; }
    sheetError('');
    sheetBusy(true);
    try {
      let data;
      if (['mkdir', 'create'].includes(sheet.type)) data = await mutate(sheet.type, { path: apiPath(sheet.path, sheet.rootId), name, ...(sheet.type === 'create' ? { content: '' } : {}) }, sheet.rootId);
      if (sheet.type === 'rename') data = await mutate('rename', { path: apiPath(sheet.entries[0].path, sheet.rootId), new_name: name }, sheet.rootId);
      if (sheet.type === 'delete') data = await mutate('delete', { paths: sheet.entries.map((entry) => apiPath(entry.path, sheet.rootId)), to_trash: false }, sheet.rootId);
      if (sheet.type === 'paste') data = await mutate(sheet.clip.action, {
        sources: sheet.entries.map((entry) => entry.path), target: apiPath(sheet.path, sheet.rootId),
        target_root_id: sheet.rootId, on_conflict: String(form.get('on_conflict') || '')
      }, sheet.clip.rootId);
      if (!data) return;
      const failures = (data.results || []).filter((result) => result.ok !== true && result.status !== 'skipped');
      const skipped = (data.results || []).filter((result) => result.status === 'skipped');
      const remaining = [...failures, ...skipped];
      if (sheet.type === 'paste' && sheet.clip.action === 'move') {
        state.clipboard.entries = sheet.entries.filter((entry) => remaining.some((result) => pathName(result.source) === pathName(entry.path)));
        if (!state.clipboard.entries.length) state.clipboard = null;
      }
      await navigate(state.path, state.rootId, { refresh: true });
      if (remaining.length) {
        sheet.entries = sheet.entries.filter((entry) => remaining.some((result) => pathName(result.source) === pathName(entry.path)));
        const targetNode = sheet.element.querySelector('.fm-target-list');
        if (targetNode) targetNode.outerHTML = targetList(sheet.entries);
        sheetError(`成功 ${data.succeeded || 0} 项，失败 ${failures.length} 项，跳过 ${skipped.length} 项。` +
          failures.map((result) => `${pathName(result.source)}：${result.error || result.status}`).join('；'));
        if (failures.some((result) => result.status === 'partial')) {
          sheet.partial = true;
          sheetError(`${sheet.element.querySelector('.fm-sheet-error').textContent}。部分文件已改变，请检查源与目标后再操作。`);
        }
        sheet.dirty = true;
        paintIcons();
      } else {
        sheet.dirty = false;
        destroySheet();
        notice('操作已完成');
      }
    } catch (error) {
      await navigate(state.path, state.rootId, { refresh: true });
      sheetError(`${errorText(error)}${error.data?.changed ? ' 文件可能已改变，请检查目录。' : ''}`);
    }
    finally {
      if (state.sheet === sheet) {
        sheetBusy(false);
        if (sheet.partial) sheet.element.querySelector('[data-fm-submit]').disabled = true;
      }
    }
  }
  function properties(entry) {
    const pairs = [['名称', entry.name], ['位置', pathName(entry.path)], ['类型', kindLabels[kind(entry)]], ['大小', entry.is_dir ? '--' : bytes(entry.size_bytes)], ['修改时间', time(entry)], ['权限', entry.mode], ['所有者', entry.owner], ['组', entry.group]];
    return `<dl class="fm-properties">${pairs.map(([label, value]) => `<div><dt>${label}</dt><dd>${escape(value || '--')}</dd></div>`).join('')}</dl>`;
  }
  function openProperties(entry) { createSheet('properties', '属性', properties(entry), `<button type="button" class="dwrt-kit-button" data-fm-close>关闭</button>`); }
  async function openEditor(entry) {
    const sheet = createSheet('editor', entry.name, '<p>正在读取文本...</p>');
    if (!sheet) return;
    sheet.entry = entry;
    sheet.controller = new AbortController();
    try {
      const data = await request('/content', { root_id: sheet.rootId, path: apiPath(entry.path, sheet.rootId) }, { signal: sheet.controller.signal });
      if (state.sheet !== sheet) return;
      sheet.baseline = data.content;
      sheet.etag = data.etag;
      // The object capability and content metadata both constrain editing.
      sheet.editable = capability('write', entry) && data.read_only !== true;
      sheet.form.innerHTML = `<label class="fm-field fm-editor"><span>${sheet.editable ? '文件内容' : '文件内容 · 只读'}</span><textarea class="dwrt-kit-input" name="content" spellcheck="false" ${sheet.editable ? '' : 'readonly'}>${escape(data.content)}</textarea></label><p class="fm-sheet-error" role="alert" hidden></p>`;
      sheet.element.querySelector('footer').innerHTML = '<div class="fm-savebar-host"></div>';
      sheet.form.querySelector('textarea').addEventListener('input', () => {
        sheet.dirty = sheet.form.elements.content.value !== sheet.baseline;
        renderSavebar(sheet);
      });
      renderSavebar(sheet);
    } catch (error) { if (state.sheet === sheet && error.name !== 'AbortError') { sheet.form.innerHTML = '<p class="fm-sheet-error" role="alert"></p>'; sheetError(errorText(error)); } }
  }
  function renderSavebar(sheet) {
    sheet.element.querySelector('.fm-savebar-host').innerHTML = kit.floatingSavebarMarkup({
      visible: sheet.editable && sheet.dirty, busy: sheet.busy, message: '文件内容已修改',
      saveLabel: '保存文件', discardLabel: '撤销', busyLabel: '保存中...'
    });
  }
  async function saveText() {
    const sheet = state.sheet;
    if (!sheet?.editable || sheet.busy || !sheet.dirty) return;
    const draft = sheet.form.elements.content.value;
    if (new TextEncoder().encode(draft).length > (state.limits.max_text_read_bytes || 262144)) { sheetError('文本超过编辑大小上限。'); return; }
    sheet.busy = true;
    sheet.form.elements.content.readOnly = true;
    renderSavebar(sheet);
    try {
      await mutate('write', { path: apiPath(sheet.entry.path, sheet.rootId), content: draft, expected_etag: sheet.etag }, sheet.rootId);
      const data = await request('/content', { root_id: sheet.rootId, path: apiPath(sheet.entry.path, sheet.rootId) });
      if (data.content !== draft) throw new Error('保存后的内容与草稿不一致，草稿已保留。');
      sheet.baseline = data.content;
      sheet.etag = data.etag;
      sheet.dirty = false;
      sheetError('');
      await navigate(state.path, state.rootId, { refresh: true });
    } catch (error) { sheetError(errorText(error)); }
    finally { sheet.busy = false; sheet.form.elements.content.readOnly = false; renderSavebar(sheet); }
  }
  async function raw(entry, signal) {
    const response = await window.DWRT_REQUEST.fetch(url('/raw', { root_id: state.rootId, path: apiPath(entry.path), disposition: 'attachment' }), { signal });
    if (!response.ok) throw Object.assign(new Error(`读取文件失败（HTTP ${response.status}）`), { status: response.status });
    return response;
  }
  async function download(entry) {
    if (!entry || !capability('download', entry)) return;
    try {
      const handle = window.showSaveFilePicker ? await window.showSaveFilePicker({ suggestedName: entry.name }) : null;
      if (!handle && entry.size_bytes > 64 * 1024 * 1024) throw new Error('当前浏览器不支持大文件直接保存，请使用支持文件保存接口的浏览器。');
      const response = await raw(entry);
      if (handle) {
        const writable = await handle.createWritable();
        try { await response.body.pipeTo(writable); } catch (error) { await writable.abort().catch(() => {}); throw error; }
      } else {
        const objectUrl = URL.createObjectURL(await response.blob());
        const link = document.createElement('a');
        link.href = objectUrl;
        link.download = entry.name;
        link.click();
        setTimeout(() => URL.revokeObjectURL(objectUrl), 60000);
      }
      notice('下载已提交');
    } catch (error) { if (error.name !== 'AbortError') notice(errorText(error), true); }
  }
  async function openPreview(entry) {
    const sheet = createSheet('preview', entry.name, '<div class="fm-preview">正在读取...</div><p class="fm-sheet-error" hidden></p>');
    if (!sheet) return;
    sheet.controller = new AbortController();
    try {
      if (entry.size_bytes > 32 * 1024 * 1024) throw new Error('文件超过 32 MB，请下载后查看。');
      const response = await raw(entry, sheet.controller.signal);
      const blob = await response.blob();
      if (state.sheet !== sheet) return;
      const objectUrl = URL.createObjectURL(blob);
      sheet.objectUrls.push(objectUrl);
      const type = kind(entry);
      const tag = type === 'image' ? `<img src="${objectUrl}" alt="${escape(entry.name)}">`
        : type === 'pdf' ? `<iframe src="${objectUrl}" sandbox="" aria-label="${escape(entry.name)}"></iframe>`
          : `<${type} src="${objectUrl}" controls preload="metadata"></${type}>`;
      sheet.element.querySelector('.fm-preview').innerHTML = tag;
      sheet.element.querySelector('.fm-preview').firstElementChild.addEventListener('error', () => sheetError('浏览器无法预览此格式，请下载后查看。'));
    } catch (error) { if (state.sheet === sheet && error.name !== 'AbortError') sheetError(errorText(error)); }
  }
  function openUpload() {
    if (!capability('upload')) return;
    const sheet = createSheet('upload', '上传文件', `<label class="fm-field"><span>文件</span><input name="files" type="file" multiple></label><span class="fm-cell-muted">${escape(state.path)}</span><div class="fm-upload-list"></div>`, `<button type="button" class="dwrt-kit-button" data-fm-close>关闭</button><button type="button" class="dwrt-kit-button" data-upload-pause disabled>${glyph('pause')}暂停</button><button type="button" class="dwrt-kit-button is-primary" data-upload-start>${glyph('upload')}开始上传</button>`);
    if (!sheet) return;
    sheet.jobs = [];
    sheet.form.elements.files.addEventListener('change', () => {
      for (const file of sheet.form.elements.files.files) sheet.jobs.push({ file, id: crypto.randomUUID(), completed: 0, status: '等待上传', done: false });
      sheet.dirty = !!sheet.jobs.length;
      sheet.form.elements.files.value = '';
      renderUploads(sheet);
    });
  }
  function renderUploads(sheet) {
    sheet.element.querySelector('.fm-upload-list').innerHTML = sheet.jobs.map((job, index) => `<div class="fm-upload-item"><span title="${escape(job.file.name)}">${escape(job.file.name)}</span><span>${bytes(job.file.size)}</span><progress class="fm-upload-progress" value="${job.completed}" max="${Math.max(1, job.file.size)}" aria-label="${escape(job.file.name)} 上传进度"></progress><span>${escape(job.status)}</span>${!job.done ? `<button type="button" class="dwrt-kit-button fm-icon-button" data-upload-cancel="${index}" title="取消上传" aria-label="取消 ${escape(job.file.name)}" ${sheet.busy ? 'disabled' : ''}>${glyph('x')}</button>` : ''}</div>`).join('');
    sheet.element.querySelector('[data-upload-start]').disabled = sheet.busy || !sheet.jobs.some((job) => !job.done);
    sheet.element.querySelector('[data-upload-pause]').disabled = !sheet.busy;
    sheet.form.elements.files.disabled = sheet.busy;
    paintIcons();
  }
  async function startUpload() {
    const sheet = state.sheet;
    if (!sheet || sheet.type !== 'upload' || sheet.busy || !capability('upload')) return;
    sheet.busy = true;
    sheet.pause = false;
    sheetError('');
    const chunkSize = 1024 * 1024;
    try {
      for (const job of sheet.jobs.filter((item) => !item.done)) {
        if (sheet.pause) break;
        job.status = '准备上传';
        renderUploads(sheet);
        try {
          const count = Math.max(1, Math.ceil(job.file.size / chunkSize));
          const data = await post('/upload/init', { root_id: sheet.rootId, dest_path: apiPath(sheet.path, sheet.rootId), filename: job.file.name, total_size: job.file.size, total_chunks: count, upload_id: job.id, overwrite: false });
          job.initialized = true;
          const uploaded = new Set(data.uploaded_chunks);
          job.completed = [...uploaded].reduce((sum, index) => sum + Math.max(0, Math.min(chunkSize, job.file.size - index * chunkSize)), 0);
          for (let index = 0; index < count; index++) {
            if (sheet.pause) break;
            if (uploaded.has(index)) continue;
            const chunk = job.file.slice(index * chunkSize, (index + 1) * chunkSize);
            job.status = '正在上传';
            renderUploads(sheet);
            await request('/upload/chunk', { root_id: sheet.rootId, upload_id: job.id, chunk_index: index }, { method: 'PUT', headers: { 'Content-Type': 'application/octet-stream' }, body: chunk });
            job.completed += chunk.size;
            renderUploads(sheet);
          }
          if (sheet.pause) { job.status = '已暂停'; break; }
          job.status = '正在合并';
          renderUploads(sheet);
          await post('/upload/complete', { root_id: sheet.rootId, upload_id: job.id });
          job.done = true;
          job.status = '已上传';
          job.completed = Math.max(1, job.file.size);
        } catch (error) { job.status = errorText(error); break; }
      }
    } finally {
      sheet.busy = false;
      sheet.dirty = sheet.jobs.some((job) => !job.done);
      renderUploads(sheet);
      await navigate(state.path, state.rootId, { refresh: true });
    }
  }
  async function cancelUpload(index) {
    const sheet = state.sheet, job = sheet?.jobs?.[index];
    if (!job || job.done || sheet.busy) return;
    sheet.busy = true;
    renderUploads(sheet);
    try {
      if (job.initialized) await post('/upload/cancel', { root_id: sheet.rootId, upload_id: job.id });
      sheet.jobs.splice(index, 1);
      sheet.dirty = sheet.jobs.some((item) => !item.done);
    } catch (error) { sheetError(errorText(error)); }
    finally { sheet.busy = false; renderUploads(sheet); }
  }

  function showFiles() {
    state.activeTool = '';
    $('#fmFiles').hidden = false;
    $('#fmToolView').hidden = true;
    sidebar(false);
  }
  function toolHasDraft() {
    try {
      const child = $('#fmToolFrame').contentWindow;
      return !child.dispatchEvent(new child.Event('beforeunload', { cancelable: true })) ||
        [...child.document.querySelectorAll('[data-dwrt-savebar]')].some((node) => !node.hidden && !node.classList.contains('is-hidden'));
    } catch (_) { return false; }
  }
  async function openTool(index) {
    const tool = state.storageTools[index];
    if (!tool) return;
    const frame = $('#fmToolFrame');
    if (frame.dataset.route && frame.dataset.route !== tool.route && toolHasDraft() && !await confirmDiscard()) return;
    state.activeTool = tool.route;
    $('#fmFiles').hidden = true;
    $('#fmToolView').hidden = false;
    $('#fmToolTitle').textContent = tool.label;
    if (frame.dataset.route !== tool.route) { frame.src = `/app/?desktop=1${tool.route}`; frame.dataset.route = tool.route; }
    frame.hidden = false;
    frame.ariaLabel = tool.label;
    sidebar(false);
    renderSidebar();
  }
  function sidebar(open) {
    app.classList.toggle('is-sidebar-open', open);
    $('.fm-rail-backdrop').hidden = !open;
  }
  async function act(action, event) {
    const selected = selectedEntries();
    if (action === 'login') return window.DWRT_SESSION.redirectToLogin();
    if (['mkdir', 'create', 'rename', 'delete'].includes(action)) return openCommand(action);
    if (action === 'open') return openEntry(selected[0]);
    if (action === 'properties' && selected[0]) return openProperties(selected[0]);
    if (action === 'copy' || action === 'cut') return remember(action === 'copy' ? 'copy' : 'move');
    if (action === 'paste') return openPaste();
    if (action === 'upload') return openUpload();
    if (action === 'download') return download(selected[0]);
    if (action === 'more') { const box = event.target.closest('button').getBoundingClientRect(); showMenu(box.left, box.bottom + 4); return; }
    if (action === 'refresh' || action === 'retry') {
      const target = action === 'retry' ? state.target : { path: state.path, rootId: state.rootId };
      return navigate(target.path, target.rootId, { refresh: true });
    }
    if (action === 'back' || action === 'forward') {
      const index = state.historyIndex + (action === 'back' ? -1 : 1), target = state.history[index];
      if (target) return navigate(target.path, target.rootId, { historyIndex: index });
    }
    if (action === 'up') return navigate(parentPath(state.path));
    if (action === 'list' || action === 'grid') { state.view = action; renderContent(); }
    if (action === 'hidden') { state.hidden = !state.hidden; state.selected.clear(); renderContent(); }
    if (action === 'sidebar' || action === 'sidebar-close') sidebar(action === 'sidebar');
    if (action === 'files') { showFiles(); renderSidebar(); }
    if (action === 'address') {
      $('#fmBreadcrumbs').hidden = true;
      $('#fmPathForm').hidden = false;
      $('#fmPath').value = state.path;
      $('#fmPath').focus();
      $('#fmPath').select();
    }
  }
  document.addEventListener('click', (event) => {
    const target = event.target.closest('button, [data-entry], input');
    if (target?.disabled) return;
    if (event.target.closest('[data-fm-close]')) { closeSheet(); return; }
    if (event.target.closest('[data-fm-submit]')) { submitSheet(); return; }
    if (event.target.closest('[data-dwrt-savebar-save]')) { saveText(); return; }
    if (event.target.closest('[data-dwrt-savebar-discard]') && state.sheet?.type === 'editor') {
      const sheet = state.sheet;
      sheet.form.elements.content.value = sheet.baseline;
      sheet.dirty = false;
      renderSavebar(sheet);
      return;
    }
    if (event.target.closest('[data-upload-start]')) { startUpload(); return; }
    if (event.target.closest('[data-upload-pause]')) { state.sheet.pause = true; return; }
    const cancel = event.target.closest('[data-upload-cancel]');
    if (cancel) { cancelUpload(Number(cancel.dataset.uploadCancel)); return; }
    const tree = event.target.closest('[data-tree]');
    if (tree) { toggleTree(tree); return; }
    const locationButton = event.target.closest('[data-path]');
    if (locationButton) { navigate(locationButton.dataset.path, locationButton.dataset.root || state.rootId); return; }
    const tool = event.target.closest('[data-tool]');
    if (tool) { openTool(Number(tool.dataset.tool)); return; }
    const open = event.target.closest('[data-open]');
    if (open) { openEntry(findEntry(open.dataset.open)); return; }
    const rowMenu = event.target.closest('[data-entry-menu]');
    if (rowMenu) {
      if (!state.selected.has(rowMenu.dataset.entryMenu)) { state.selected = new Set([rowMenu.dataset.entryMenu]); updateSelection(); }
      const rect = rowMenu.getBoundingClientRect();
      showMenu(rect.left, rect.bottom);
      return;
    }
    const actionButton = event.target.closest('[data-action]');
    if (actionButton) { if (actionButton.dataset.action !== 'more') closeMenu(); act(actionButton.dataset.action, event); return; }
    const sort = event.target.closest('[data-sort]');
    if (sort) {
      state.direction = state.sort === sort.dataset.sort ? -state.direction : 1;
      state.sort = sort.dataset.sort;
      renderContent();
      return;
    }
    if (target?.id === 'fmSelectAll') {
      state.selected = target.checked ? new Set(visibleEntries().map((entry) => entry.path)) : new Set();
      updateSelection();
      return;
    }
    const row = event.target.closest('[data-entry]');
    if (row) { selectEntry(row.dataset.entry, event); return; }
    if (event.target === content || event.target.classList.contains('fm-grid')) { state.selected.clear(); updateSelection(); }
    if (!event.target.closest('#fmMenu')) closeMenu();
  });
  content.addEventListener('dblclick', (event) => {
    if (!event.target.closest('button,input')) openEntry(findEntry(event.target.closest('[data-entry]')?.dataset.entry));
  });
  content.addEventListener('contextmenu', (event) => {
    event.preventDefault();
    const row = event.target.closest('[data-entry]');
    if (row && !state.selected.has(row.dataset.entry)) { state.selected = new Set([row.dataset.entry]); updateSelection(); }
    if (!row) { state.selected.clear(); updateSelection(); }
    showMenu(event.clientX, event.clientY);
  });
  $('#fmSearchForm').addEventListener('submit', (event) => { event.preventDefault(); search(); });
  function cancelPendingSearch() {
    if (state.searchPending) {
      ++state.sequence;
      state.controller?.abort();
      state.searchPending = false;
      state.loading = false;
      state.error = '';
    }
  }
  $('#fmSearch').addEventListener('input', () => {
    cancelPendingSearch();
    if ($('#fmSearchScope').value === 'current' || !$('#fmSearch').value) {
      state.query = $('#fmSearch').value;
      state.searchResults = null;
      state.selected.clear();
    }
    renderContent();
  });
  $('#fmSearchScope').addEventListener('change', () => {
    cancelPendingSearch();
    state.searchResults = null;
    state.query = $('#fmSearch').value;
    renderContent();
  });
  $('#fmPathForm').addEventListener('submit', (event) => {
    event.preventDefault();
    const path = pathName($('#fmPath').value);
    const root = state.roots.filter((item) => path === pathName(item.path) || path.startsWith(`${pathName(item.path) === '/' ? '' : pathName(item.path)}/`))
      .sort((a, b) => b.path.length - a.path.length)[0];
    $('#fmPathForm').hidden = true;
    $('#fmBreadcrumbs').hidden = false;
    if (root) navigate(path, root.id); else notice('路径不属于任何可访问的存储空间。', true);
  });
  window.addEventListener('click', (event) => {
    if (!event.target.closest('[data-fm-close]') || !state.sheet || state.confirming) return;
    if (state.sheet.busy || state.sheet.dirty) { event.preventDefault(); event.stopImmediatePropagation(); closeSheet(); }
  }, true);
  window.addEventListener('keydown', (event) => {
    if (event.key === 'Escape' && state.confirming) {
      event.preventDefault(); event.stopImmediatePropagation();
      $('#fmConfirmHost [data-dwrt-confirm-cancel]')?.click();
      return;
    }
    if (event.key === 'Escape' && state.sheet && !state.confirming && (state.sheet.dirty || state.sheet.busy)) {
      event.preventDefault(); event.stopImmediatePropagation(); closeSheet();
    }
  }, true);
  window.addEventListener('pointerdown', (event) => {
    // Kit's swipe dismiss animates before replaying close; keep drafts onscreen.
    if ((state.sheet?.dirty || state.sheet?.busy) && event.target.closest('.fm-sheet .dwrt-kit-sheet-header') &&
        !event.target.closest('button, input, select, textarea, a')) {
      event.preventDefault(); event.stopImmediatePropagation();
    }
  }, true);
  document.addEventListener('keydown', (event) => {
    if (!$('#fmMenu').hidden) {
      const buttons = [...$('#fmMenu').querySelectorAll('button:not(:disabled)')];
      const index = buttons.indexOf(document.activeElement);
      if (event.key === 'ArrowDown' || event.key === 'ArrowUp') {
        event.preventDefault();
        buttons[(index + (event.key === 'ArrowDown' ? 1 : buttons.length - 1)) % buttons.length]?.focus();
      }
      if (event.key === 'Escape') { closeMenu(); content.focus(); }
      return;
    }
    if (state.sheet || event.target.closest('input,textarea,select,[contenteditable]')) {
      if (event.key === 'Escape' && event.target === $('#fmPath')) { $('#fmPathForm').hidden = true; $('#fmBreadcrumbs').hidden = false; }
      return;
    }
    if (event.key === 'Escape') { state.selected.clear(); sidebar(false); updateSelection(); }
    if (event.key === 'Enter' && event.target.closest('[data-entry]')) { event.preventDefault(); openEntry(findEntry(event.target.closest('[data-entry]').dataset.entry)); }
    if (event.key === 'F2') { event.preventDefault(); openCommand('rename'); }
    if (event.key === 'Delete') { event.preventDefault(); openCommand('delete'); }
    if (event.altKey && event.key === 'ArrowUp') { event.preventDefault(); act('up', event); }
    if (event.ctrlKey || event.metaKey) {
      const key = event.key.toLowerCase();
      if (['a', 'c', 'x', 'v', 'l'].includes(key)) {
        event.preventDefault();
        if (key === 'a') { state.selected = new Set(visibleEntries().map((entry) => entry.path)); updateSelection(); }
        if (key === 'c' || key === 'x') remember(key === 'c' ? 'copy' : 'move');
        if (key === 'v') openPaste();
        if (key === 'l') act('address', event);
      }
    }
  });
  addEventListener('beforeunload', (event) => {
    if (state.sheet?.dirty || state.sheet?.busy || toolHasDraft()) { event.preventDefault(); event.returnValue = ''; }
  });
  addEventListener('pagehide', () => { state.controller?.abort(); state.sheet?.controller?.abort(); });
  addEventListener('message', (event) => {
    if (event.origin !== location.origin || event.source !== parent || event.data?.type !== 'dwrt-file-manager:context') return;
    state.storageTools = (event.data.tools || []).filter((tool) => typeof tool.route === 'string' && /^#\/storage(?:\/[a-z-]+)?$/.test(tool.route) && tool.route !== '#/storage/files' && !tool.disabled);
    renderSidebar();
  });
  $('#fmToolFrame').addEventListener('load', () => {
    try { $('#fmToolFrame').contentDocument.addEventListener('pointerdown', () => window.dispatchEvent(new Event('focus')), true); } catch (_) {}
  });
  async function boot() {
    if (document.documentElement.dataset.desktopApp === 'true') {
      const host = parent.document.getElementById('desktopRoot');
      const wallpaper = host?.querySelector('.desktop-wallpaper img');
      const source = document.createElement('img');
      source.id = 'appWallpaper';
      source.hidden = true;
      source.alt = '';
      document.body.append(source);
      const followTheme = () => {
        const root = document.documentElement;
        root.dataset.themeFamily = parent.document.documentElement.dataset.themeFamily || root.dataset.themeFamily;
        root.dataset.themeResolved = parent.document.documentElement.dataset.themeResolved || root.dataset.themeResolved;
        if (!host) return;
        const style = parent.getComputedStyle(host);
        ['base-blur', 'neutral-density', 'neutral-density-raised', 'neutral-color', 'saturation', 'highlight-strength'].forEach((key) => {
          const token = `--dwrt-glass-${key}`;
          root.style.setProperty(token, style.getPropertyValue(token));
        });
        if (wallpaper && frameElement) {
          const src = wallpaper.currentSrc || wallpaper.src;
          if (source.src !== src) source.src = src;
          const imageStyle = parent.getComputedStyle(wallpaper);
          ['objectFit', 'objectPosition', 'filter', 'opacity'].forEach((key) => { source.style[key] = imageStyle[key]; });
          const imageRect = wallpaper.getBoundingClientRect(), frameRect = frameElement.getBoundingClientRect();
          const geometry = { width: imageRect.width, height: imageRect.height,
            right: frameRect.right - imageRect.right, top: imageRect.top - frameRect.top };
          Object.entries(geometry).forEach(([key, value]) => root.style.setProperty(`--fm-wallpaper-${key}`, `${value}px`));
        }
      };
      followTheme();
      const observer = new MutationObserver(followTheme);
      observer.observe(parent.document.documentElement, { attributes: true, attributeFilter: ['data-theme-family', 'data-theme-resolved'] });
      if (host) observer.observe(host, { attributes: true, attributeFilter: ['style'] });
      if (wallpaper) observer.observe(wallpaper, { attributes: true, attributeFilter: ['src', 'style'] });
      const desktopWindow = frameElement?.closest('.desktop-window');
      if (desktopWindow) observer.observe(desktopWindow, { attributes: true, attributeFilter: ['style', 'class'] });
      addEventListener('resize', followTheme);
      addEventListener('pagehide', () => observer.disconnect(), { once: true });
    }
    paintIcons();
    kit.mountAll(app);
    const gate = window.DWRT_SESSION;
    if (!await gate.ensureFresh()) { state.sessionRequired = true; state.error = '请登录后查看文件。'; renderContent(); return; }
    state.role = gate.tokens().role;
    if (parent !== window) parent.postMessage({ type: 'dwrt-file-manager:ready' }, location.origin);
    await navigate('/');
  }
  boot();
})();
