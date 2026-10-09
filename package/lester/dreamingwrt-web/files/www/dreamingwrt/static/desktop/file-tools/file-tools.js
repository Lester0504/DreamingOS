(() => {
  'use strict';
  const api = window.DWRT_FILES, kit = window.DWRT_UI_KIT;
  const mode = document.body.dataset.fileTool;
  const $ = (s) => document.querySelector(s);
  const workspace = $('#ftWorkspace');
  const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const icon=name=>kit.lucideIcon(name,{size:20,strokeWidth:1.7});
  const commandIcons={new:'file-plus',open:'folder-open',save:'save','save-as':'save-all',undo:'undo-2',redo:'redo-2','toggle-find':'search',compare:'columns-2',previous:'chevron-left',next:'chevron-right','zoom-out':'zoom-out','zoom-in':'zoom-in',fit:'maximize',reset:'rotate-ccw','rotate-left':'rotate-ccw','rotate-right':'rotate-cw',download:'download','media-retry':'refresh-cw'};
  const btn = (action, label, disabled = false) => {const iconOnly=['undo','redo','toggle-find','compare','previous','next','zoom-out','zoom-in','fit','rotate-left','rotate-right','reset'].includes(action);return `<button type="button" data-dwrt-component="${iconOnly?'icon-button':'button'}" data-variant="ghost" class="dwrt-kit-button${iconOnly?' dwrt-kit-icon-button':''}" data-command="${action}" aria-label="${esc(label)}" title="${esc(label)}" ${disabled ? 'disabled' : ''}>${icon(commandIcons[action]||'')}${iconOnly?'':`<span>${label}</span>`}</button>`;};
  const parentPath = (s) => api.path(s).split('/').slice(0, -1).join('/') || '/';
  const imageType = (file) => /\.(png|jpe?g|gif|webp|avif|bmp)$/i.test(file.name);
  const audioType = (file) => /\.(mp3|wav|ogg|flac|m4a|aac|opus)$/i.test(file.name);
  const docs = [], state = { active: null, file: null, siblings: [], index: 0, request: 0, controller: null, picker: null, media: null, rotation: 0, zoom: 1, x: 0, y: 0, saving: false };
  let cookieTimer, textTools, textToolsLoading;
  function loadTextTools() {
    if (textTools) return Promise.resolve(textTools);
    if (!textToolsLoading) textToolsLoading = new Promise((resolve, reject) => {
      const script = document.createElement('script'); script.src = '/static/desktop/file-tools/text-tools.js?v=20261005-text-01';
      script.onload = () => { textTools = window.DWRT_TEXT_TOOLS({ api, notice }); textTools.activate(state.active); resolve(textTools); };
      script.onerror = () => { script.remove(); textToolsLoading = null; reject(new Error('文本工具加载失败，请重试。')); };
      document.head.append(script);
    });
    return textToolsLoading;
  }
  function notice(message = '') { $('#ftNotice').textContent = message; $('#ftNotice').hidden = !message; }
  function failure(error) {
    if (error.name === 'AbortError') return;
    const messages = { revision_conflict: '文件已被其他窗口修改，当前草稿已保留。可点击“比较差异”查看磁盘最新内容，或另存为。', file_exists: '目标文件已存在，请选择其他名称。', text_too_large: '文本超过 256 KiB，无法编辑。', not_utf8_text: '该文件不是 UTF-8 文本。', content_protected: '该文件受保护，不能读取。', upload_metadata_conflict: '上传信息与原任务不一致。' };
    notice(messages[error.code] || error.message || '文件无法读取，请重试。');
  }
  async function discardConfirmed() {
    if (document.querySelector('[data-ft-confirm]')) return false;
    const host = document.createElement('div'); host.dataset.ftConfirm = '';
    host.innerHTML = kit.confirmationMarkup({ title: '放弃未保存的更改？', description: '关闭后，这个文件的草稿将不再保留。', confirmLabel: '放弃更改', cancelLabel: '继续编辑' });
    document.body.append(host); kit.mountAll(host);
    return new Promise((resolve) => {
      host.addEventListener('click', (event) => {
        const accept = event.target.closest('[data-dwrt-confirm-accept]');
        if (!accept && !event.target.closest('[data-dwrt-confirm-cancel]')) return;
        kit.unmount(host); host.remove(); resolve(!!accept);
      });
    });
  }
  function dirty(doc) { return doc.fresh || doc.area.value !== doc.baseline; }
  function updateText() {
    const doc = state.active;
    document.body.dataset.dirty=String(!!doc&&doc.editable&&dirty(doc));
    $('#ftEditorEmpty').hidden=!!doc;
    $('#ftTabs').innerHTML = docs.map((item, i) => `<div class="ft-tab"><button data-dwrt-component="button" class="dwrt-kit-button ft-tab-name" data-tab="${i}" aria-pressed="${item === doc}">${esc(item.file.name)}${dirty(item) ? ' · 未保存' : ''}</button><button data-dwrt-component="button" class="dwrt-kit-button" data-close-tab="${i}" aria-label="关闭 ${esc(item.file.name)}" title="关闭文件" data-variant="ghost">${icon('x')}</button></div>`).join('');
    $('#ftSavebar').innerHTML = kit.floatingSavebarMarkup({ visible: !!doc && doc.editable && dirty(doc), busy: state.saving, message: '文件内容已修改', saveLabel: doc?.fresh ? '另存为' : '保存文件', discardLabel: '撤销更改' });
    $('#ftFilename').textContent = doc?.file.path || '';
    $('#ftLanguage').disabled = !doc;
    $('#ftLanguage').value = doc?.language || 'plain';
    document.querySelector('[data-command="compare"]').disabled = !doc || state.saving;
    document.querySelector('[data-command="save"]').disabled=!doc||!doc.editable||!dirty(doc)||state.saving;
    document.querySelector('[data-command="save-as"]').disabled=!doc||!doc.editable||state.saving;
    textTools?.update(doc);
    if (!doc) { $('#ftPosition').textContent = '尚未打开文件'; return; }
    const before = doc.area.value.slice(0, doc.area.selectionStart);
    $('#ftPosition').textContent = `第 ${before.split('\n').length} 行，第 ${before.length - before.lastIndexOf('\n')} 列 · UTF-8 · ${new TextEncoder().encode(doc.area.value).length.toLocaleString()} 字节${doc.editable ? '' : ' · 只读'}`;
    document.querySelector('[data-command="save-as"]').disabled = !doc.editable || state.saving;
  }
  function activate(doc) { state.active = doc; docs.forEach((d) => { d.container.hidden = d !== doc; }); textTools?.activate(doc); updateText(); doc?.area.focus(); }
  function addDocument(file, data, fresh = false) {
    const area = document.createElement('textarea'); area.className = 'dwrt-kit-input ft-editor'; area.spellcheck = false; area.setAttribute('aria-label', `${file.name} 文件内容`); area.value = data.content || ''; area.wrap = 'soft';
    const container = document.createElement('div'); container.className = 'ft-document'; container.append(area);
    const doc = { file, area, container, language: 'plain', baseline: area.value, etag: data.etag, fresh, editable: fresh || (api.can(file, 'write') && data.read_only !== true), undo: [], redo: [], previous: area.value };
    area.readOnly = !doc.editable;
    area.addEventListener('input', () => { doc.undo.push(doc.previous); if (doc.undo.length > 60) doc.undo.shift(); doc.previous = area.value; doc.redo = []; updateText(); });
    ['keyup','click','select'].forEach((name) => area.addEventListener(name, updateText));
    $('#ftEditors').append(container); docs.push(doc); activate(doc);
  }
  function editValue(value) {
    const doc = state.active; if (!doc?.editable || state.saving) return;
    doc.undo.push(doc.area.value); doc.redo = []; doc.area.value = value; doc.previous = value; updateText();
  }
  function history(undo) {
    const doc = state.active; if (!doc?.editable || state.saving) return;
    const from = undo ? doc.undo : doc.redo, to = undo ? doc.redo : doc.undo;
    if (!from.length) return;
    to.push(doc.area.value); doc.area.value = from.pop(); doc.previous = doc.area.value; updateText();
  }
  async function save(destination) {
    const doc = state.active;
    if (!doc?.editable || state.saving) return;
    if (!destination && doc.fresh) { await picker(true); return; }
    const draft = doc.area.value;
    if (new TextEncoder().encode(draft).length > 262144) { notice('文本超过 256 KiB，草稿已保留。'); return; }
    state.saving = true; doc.area.readOnly = true; updateText();
    try {
      const file = destination || doc.file;
      const result = await api.post('/mutate', destination ? { root_id: file.root_id, path: parentPath(file.path), name: file.name, content: draft, action: 'create', confirm: true }
        : { root_id: file.root_id, path: file.path, content: draft, action: 'write', expected_etag: doc.etag, confirm: true });
      if (result.persisted !== true) throw new Error('文件尚未确认保存，草稿已保留。');
      const readback = await api.request('/content', { root_id: file.root_id, path: file.path });
      if (readback.content !== draft) throw new Error('保存回读与草稿不一致，草稿已保留。');
      doc.file = { ...file, capabilities: { read: true, write: true } }; doc.fresh = false; doc.baseline = draft; doc.etag = readback.etag; doc.conflicted = false;
      notice('文件已保存并核对内容。'); closePicker();
    } catch (error) { if (error.code === 'revision_conflict') doc.conflicted = true; failure(error); }
    finally { state.saving = false; doc.area.readOnly = !doc.editable; updateText(); }
  }
  function findNext() {
    const doc = state.active, needle = $('#ftFind').value; if (!doc || !needle) return;
    let index = doc.area.value.indexOf(needle, doc.area.selectionEnd);
    if (index < 0) index = doc.area.value.indexOf(needle);
    if (index < 0) { notice('未找到匹配内容。'); return; }
    doc.area.focus(); doc.area.setSelectionRange(index, index + needle.length); updateText();
  }
  function textUI() {
    $('#fileTool > header').hidden=true;
    $('#fileTool > header').innerHTML='<span id="ftFilename"></span>';
    workspace.innerHTML = `<div class="ft-toolbar ft-edit-controls" aria-label="编辑工具"><div class="ft-tool-group">${btn('new','新建')}${btn('open','打开')}${btn('save','保存')}${btn('save-as','另存为')}</div><div class="ft-tool-group">${btn('undo','撤销')}${btn('redo','重做')}</div><div class="ft-tool-group">${btn('toggle-find','查找')}${btn('compare','比较差异',true)}</div></div><nav id="ftTabs" class="ft-tabs" aria-label="打开的文件"></nav><details id="ftSearchPanel" class="ft-search-panel"><summary>查找与替换</summary><div class="ft-toolbar ft-search"><label class="dwrt-kit-field">查找<input id="ftFind" class="dwrt-kit-input" type="search"></label>${btn('find','下一个')}<label class="dwrt-kit-field">替换为<input id="ftReplace" class="dwrt-kit-input"></label>${btn('replace','替换选中')}${btn('replace-all','全部替换')}</div></details><div id="ftEditors" class="ft-editors dwrt-kit-field"><div id="ftEditorEmpty" class="ft-empty"><span class="ft-empty-icon">${icon('file-pen-line')}</span><strong>开始编辑</strong><p>打开一个 UTF-8 文本，或新建文件。</p><p>⌘ / Ctrl + O 打开 · ⌘ / Ctrl + N 新建</p></div></div><footer class="ft-statusbar"><span id="ftPosition" class="ft-status">尚未打开文件</span><label class="dwrt-kit-field ft-language">语法<select id="ftLanguage" class="dwrt-kit-select" aria-label="语法" disabled><option value="plain">纯文本</option><option value="auto">按文件类型</option><option value="json">JSON</option><option value="javascript">JavaScript</option><option value="markup">HTML / XML</option><option value="css">CSS</option><option value="bash">Shell</option><option value="ini">INI / 配置</option><option value="python">Python</option><option value="yaml">YAML</option></select></label><label class="dwrt-kit-field ft-wrap"><input id="ftWrap" type="checkbox" checked> 自动换行</label></footer>`;
    updateText();
  }
  function cleanupMedia() {
    clearInterval(cookieTimer);
    state.playback?.dispose(); state.playback=null;
    if (state.media) { state.media.pause(); state.media.removeAttribute('src'); state.media.load(); state.media = null; }
  }
  function transform() { const img = $('#ftImage'); if (img) img.style.transform = `translate(${state.x}px, ${state.y}px) scale(${state.zoom}) rotate(${state.rotation}deg)`; $('#ftZoom')?.replaceChildren(document.createTextNode(`${Math.round(state.zoom * 100)}%`)); }
  function resetImage() { state.zoom = 1; state.rotation = state.x = state.y = 0; transform(); }
  async function openFile(context) {
    const sequence = ++state.request;
    state.controller?.abort(); state.controller = new AbortController();
    notice('正在读取文件…');
    try {
      if (!['admin','owner'].includes(window.DWRT_SESSION.tokens().role)) throw new Error('当前账号没有文件内容读取权限。');
      const list = await api.request('', { root_id: context.root_id, path: parentPath(context.path) }, { signal: state.controller.signal });
      if (sequence !== state.request) return;
      const entry = list.entries.find((e) => api.path(e.path) === api.path(context.path));
      if (!entry) throw new Error(list.entries_truncated ? '此目录条目过多，当前列表未包含该文件。' : '文件已移走或不存在。');
      const file = { ...entry, root_id: list.root_id };
      if (!api.can(file, mode === 'text-editor' ? 'read' : 'preview')) throw new Error('当前文件未开放此操作。');
      if (mode === 'text-editor') {
        const existing = docs.find((d) => d.file.root_id === file.root_id && d.file.path === file.path);
        if (existing) { activate(existing); notice(); return; }
        const data = await api.request('/content', { root_id: file.root_id, path: file.path }, { signal: state.controller.signal });
        if (sequence !== state.request) return;
        addDocument(file, data); notice(); return;
      }
      const source = await api.stream(file, { signal: state.controller.signal });
      if (sequence !== state.request) return;
      cleanupMedia(); document.querySelector('.ft-context-tools')?.remove(); state.file = file; $('#ftFilename').textContent = file.name;
      if (mode === 'image-viewer') {
        state.siblings = list.entries.filter((e) => imageType(e) && api.can(e,'preview')).map((e) => ({ ...e, root_id: list.root_id }));
        state.index = state.siblings.findIndex((e) => e.path === file.path);
        workspace.innerHTML = `<div class="ft-toolbar ft-context-tools">${btn('previous','上一张',state.index<=0)}${btn('next','下一张',state.index<0||state.index>=state.siblings.length-1)}${btn('zoom-out','缩小')}${btn('zoom-in','放大')}<output id="ftZoom">100%</output>${btn('fit','适应窗口')}<details class="ft-more"><summary>更多</summary><div>${btn('rotate-left','向左旋转')}${btn('rotate-right','向右旋转')}${btn('reset','重置')}${btn('download','下载原图',!api.can(file,'download'))}</div></details></div><div id="ftCanvas" class="ft-canvas" tabindex="0" aria-label="图片工作区，方向键切换图片，加减键缩放"><img id="ftImage" alt="${esc(file.name)}" draggable="false"></div><footer id="ftImageInfo" class="ft-status"></footer>`;
        $('#fileTool > header').append(workspace.querySelector('.ft-context-tools'));
        const img = $('#ftImage'); img.onload = () => { $('#ftImageInfo').textContent = `${img.naturalWidth} × ${img.naturalHeight} · ${Number(file.size_bytes).toLocaleString()} 字节 · ${file.path}`; }; img.onerror = () => notice('浏览器无法显示此图片格式，可下载原文件。'); img.src = source; resetImage();
        const canvas = $('#ftCanvas'); let drag;
        canvas.addEventListener('wheel', (event) => { event.preventDefault(); state.zoom = Math.max(.1,Math.min(8,state.zoom * (event.deltaY<0?1.1:1/1.1))); transform(); }, { passive:false });
        canvas.addEventListener('dblclick', () => { state.zoom = state.zoom===1?2:1; transform(); });
        canvas.addEventListener('pointerdown', (event) => { drag={x:event.clientX,y:event.clientY,ox:state.x,oy:state.y}; canvas.setPointerCapture(event.pointerId); });
        canvas.addEventListener('pointermove', (event) => { if(drag) {state.x=drag.ox+event.clientX-drag.x;state.y=drag.oy+event.clientY-drag.y;transform();} });
        canvas.addEventListener('pointerup', () => {drag=null;}); canvas.addEventListener('pointercancel', () => {drag=null;});
      } else {
        const audio = audioType(file);
        workspace.innerHTML = `<div class="ft-media-stage">${audio?`<div class="ft-audio-info"><strong>${esc(file.name)}</strong><p>${Number(file.size_bytes).toLocaleString()} 字节 · 音频文件</p></div>`:''}<${audio?'audio':'video'} id="ftMedia" controls preload="metadata" aria-label="${esc(file.name)}"></${audio?'audio':'video'}></div><details class="ft-more ft-media-options"><summary>媒体详情与更多操作</summary><div class="ft-toolbar">${btn('media-retry','重新连接')}${btn('download','下载原文件',!api.can(file,'download'))}</div><div id="ftPlayback"></div></details>`;
        const media = $('#ftMedia'); state.media=media; state.playback=window.DWRT_MEDIA_PLAYBACK.attach(media,file,$('#ftPlayback'),{source});
        media.addEventListener('error', () => notice('播放失败：文件可能无法解码、已移走或会话已失效。可重新连接或下载原文件。'));
        cookieTimer=setInterval(async()=>{ if(!await window.DWRT_SESSION.ensureFresh({skewMs:60000})) {media.pause();notice('会话已过期，请重新登录后继续播放。');} },30000);
      }
      notice();
    } catch (error) { if(sequence===state.request) failure(error); }
  }
  function closePicker() {
    if (!state.picker) return;
    state.picker.controller?.abort(); kit.unmount(state.picker.host);
    state.picker.sheet?.remove(); state.picker.overlay?.remove(); state.picker.host.remove(); state.picker=null;
  }
  async function picker(saveAs=false) {
    if (state.saving) return;
    const selected = await window.DWRT_PICK_FILE({ title: saveAs ? '另存为' : '打开文件',
      saveName: saveAs ? state.active?.file.name || '未命名.txt' : '', writable: saveAs,
      root_id: state.active?.file.root_id || '', path: state.active ? parentPath(state.active.file.path) : '/',
      accept: e => mode === 'text-editor' ? e.capabilities?.read : mode === 'image-viewer' ? imageType(e) : /\.(mp4|webm|ogv|mov|mkv|mp3|wav|ogg|flac|m4a|aac|opus)$/i.test(e.name) });
    if (selected) return saveAs ? save(selected) : openFile(selected);
  }
  async function command(action) {
    if(action==='open')return picker();
    if(action==='save')return save();
    if(action==='toggle-find'){$('#ftSearchPanel').open=!$('#ftSearchPanel').open;if($('#ftSearchPanel').open)$('#ftFind').focus();return;}
    if(action==='new') {if(!['admin','owner'].includes(window.DWRT_SESSION.tokens().role))return;addDocument({name:'未命名.txt',path:'/',root_id:''},{content:''},true);return;}
    if(action==='save-as')return picker(true);
    if(action==='compare'){const doc=state.active;if(!doc||state.saving)return;const tools=await loadTextTools();if(state.active===doc)tools.showComparison(doc);return;}
    if(action==='undo'||action==='redo')return history(action==='undo');
    if(action==='find')return findNext();
    if(action==='replace'||action==='replace-all') {
      const doc=state.active,needle=$('#ftFind').value,replacement=$('#ftReplace').value;if(!doc?.editable||!needle)return;
      if(action==='replace-all')editValue(doc.area.value.split(needle).join(replacement));
      else if(doc.area.value.slice(doc.area.selectionStart,doc.area.selectionEnd)===needle)editValue(doc.area.value.slice(0,doc.area.selectionStart)+replacement+doc.area.value.slice(doc.area.selectionEnd));
      return;
    }
    if(action==='previous'||action==='next'){const file=state.siblings[state.index+(action==='next'?1:-1)];if(file)return openFile(file);return;}
    if(action==='zoom-in'||action==='zoom-out'){state.zoom=Math.max(.1,Math.min(8,state.zoom*(action==='zoom-in'?1.25:.8)));transform();}
    if(action==='rotate-left'||action==='rotate-right'){state.rotation+=action==='rotate-left'?-90:90;transform();}
    if(action==='fit'||action==='reset')resetImage();
    if(action==='download'&&state.file&&api.can(state.file,'download')){const link=document.createElement('a');link.href=await api.stream(state.file,{disposition:'attachment'});link.download=state.file.name;link.click();}
    if(action==='media-retry'&&state.file) { const at=state.media?.currentTime||0; await openFile(state.file);state.media?.addEventListener('loadedmetadata',()=>{state.media.currentTime=at;},{once:true}); }
  }
  document.addEventListener('click',async(event)=>{
    try {
      const tab=event.target.closest('[data-tab]');if(tab){activate(docs[Number(tab.dataset.tab)]);return;}
      const close=event.target.closest('[data-close-tab]');if(close&&!state.saving){const doc=docs[Number(close.dataset.closeTab)];if(dirty(doc)&&!await discardConfirmed())return;docs.splice(docs.indexOf(doc),1);textTools?.dispose(doc);doc.container.remove();activate(docs.at(-1)||null);return;}
      if(event.target.closest('[data-dwrt-savebar-save]'))return save();
      if(event.target.closest('[data-dwrt-savebar-discard]')){if(state.active&&!state.saving){if(state.active.fresh){const doc=state.active;docs.splice(docs.indexOf(doc),1);textTools?.dispose(doc);doc.container.remove();activate(docs.at(-1)||null);}else{editValue(state.active.baseline);updateText();}}return;}
      const action=event.target.closest('[data-command]');if(action&&!action.disabled)await command(action.dataset.command);
    } catch(error){failure(error);}
  });
  document.addEventListener('change',async(event)=>{
    if(event.target.id==='ftWrap')docs.forEach((doc)=>{doc.area.wrap=event.target.checked?'soft':'off';textTools?.update(doc);});
    if(event.target.id==='ftLanguage'){
      const doc=state.active,value=event.target.value;if(!doc)return;doc.language=value;
      if(value==='plain'&&!textTools)return;
      try{const tools=await loadTextTools();if(docs.includes(doc))tools.language(doc,doc.language);}catch(error){failure(error);}
    }
  });
  document.addEventListener('keydown',(event)=>{
    if(document.querySelector('.ft-picker'))return;
    if(document.querySelector('.ft-comparison')){if(event.key==='Escape')textTools?.closeComparison();if((event.metaKey||event.ctrlKey)&&event.key==='s')event.preventDefault();return;}
    if(event.key==='Escape'&&state.picker){closePicker();return;}
    if(mode==='text-editor'&&(event.metaKey||event.ctrlKey)) {
      if(event.key==='o'||event.key==='n'){event.preventDefault();command(event.key==='o'?'open':'new').catch(failure);}
      if(event.key==='s'){event.preventDefault();save().catch(failure);}
      if(event.key==='z'){event.preventDefault();history(!event.shiftKey);}
      if(event.key==='f'){event.preventDefault();$('#ftSearchPanel').open=true;$('#ftFind').focus();}
    } else if(mode==='image-viewer'&&!state.picker&&!/INPUT|TEXTAREA|SELECT/.test(event.target.tagName)) {
      const action={ArrowLeft:'previous',ArrowRight:'next','+':'zoom-in','=':'zoom-in','-':'zoom-out','0':'fit'}[event.key];if(action){event.preventDefault();command(action).catch(failure);}
    }
  });
  addEventListener('beforeunload',(event)=>{if(state.saving||docs.some(dirty)){event.preventDefault();event.returnValue='';}});
  addEventListener('pagehide',()=>{state.controller?.abort();closePicker();cleanupMedia();textTools?.destroy();});
  addEventListener('message',(event)=>{if(event.origin===location.origin&&event.source===parent&&event.data?.type==='dwrt-files:context'&&event.data.context)openFile(event.data.context);});
  async function boot(){
    kit.mountAll($('#fileTool'));if(mode==='text-editor')textUI();else workspace.innerHTML=`<div class="ft-empty"><span class="ft-empty-icon">${icon(mode==='image-viewer'?'image':'circle-play')}</span><strong>${mode==='image-viewer'?'打开图片':'打开音频或视频'}</strong><p>${mode==='image-viewer'?'在画布中缩放、旋转，或浏览同目录图片。':'播放本机文件，支持原生流式读取。'}</p>${btn('open','选择文件')}</div>`;
    if(!await window.DWRT_SESSION.ensureFresh()){notice('请登录后打开文件。');return;}
    const permitted=['admin','owner'].includes(window.DWRT_SESSION.tokens().role);
    document.querySelectorAll('[data-command="open"],[data-command="new"]').forEach((button)=>{button.disabled=!permitted;});
    if(!permitted)notice('当前账号没有文件内容读取权限。');
    const query=new URLSearchParams(location.search);if(query.has('path')&&permitted)await openFile(Object.fromEntries(query));
    if(parent!==window)parent.postMessage({type:'dwrt-files:ready',appId:mode},location.origin);
  }
  boot().catch(failure);
})();
