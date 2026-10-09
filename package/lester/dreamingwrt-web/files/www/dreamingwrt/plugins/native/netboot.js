// Independently authored DreamingWrt Netboot workbench; both hosts mount this module.
const VERSION = '20261002-netboot-04';
const clone = (value) => JSON.parse(JSON.stringify(value));
const escape = (value) => String(value ?? '').replace(/[&<>"']/g, (c) => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const labels = {stopped:'已停用',running:'服务运行中',degraded:'部分服务不可用',failed:'已启用但不可用',ready:'启动文件就绪',unmounted:'未挂载',missing:'源文件不可用',mount_failed:'挂载失败',unsupported:'模板未支持',busy:'正在传输',manual:'手动登记',observed:'被动发现',menu:'请求菜单','boot-script-requested':'请求启动脚本',denied:'访问被拒绝','service-operation-failed':'服务操作失败',dhcp_attach:'DHCP 附加模式'};
const reasons = {revision_conflict:'配置已被其他操作修改，草稿已保留，请检查后重新保存。',preflight_changed:'预检后环境发生变化，请重新预检。',no_interface_selected:'请选择一个 LAN。',interface_unavailable:'LAN 地址尚不可用。',dhcp_mode_unavailable:'该 LAN 没有启用本机 DHCP 池；暂不支持 proxyDHCP。',multi_lan_not_supported:'当前版本一次只能发布到一个 LAN。',boot_file_missing:'缺少引导文件。',resource_manifest_missing:'引导文件缺少来源、版本或许可证记录。',port_in_use:'HTTP 端口被占用。',dhcp_option_conflict:'已有手工 PXE 选项与内网启动冲突。',existing_pxe_configuration:'已有独立 PXE/TFTP 配置，请先处理配置归属。',image_busy:'镜像仍有活跃传输，请稍后重试。',source_changed:'源文件已替换，请重挂载并重新识别。',template_not_supported:'该镜像不属于当前支持的 RHEL 9 x86_64 HTTP 模板。',duplicate_mac:'该 MAC 已有授权记录。',capability_disabled:'当前版本未开放此能力。',apply_failed:'配置应用失败，请查看原始错误与恢复结果。'};
const detail = (value) => reasons[value] || labels[value] || value || '未返回';
const time = (v) => v ? new Date(v * 1000).toLocaleString('zh-CN') : '尚未访问';

export function mount(context = {}) {
  const root = context.root || document.getElementById('routePreview');
  const ui = context.ui || window.DWRT_UI_KIT || {};
  const state = {mounted:true,tab:'overview',loading:true,busy:false,revision:0,data:{},errors:{},draft:null,baseline:null,baselineRevision:0,editor:null,notice:'',confirmation:null,seq:0,logOffset:0};
  const desktop = document.body.classList.contains('netboot-app');
  const stage=root.closest('.console-stage');stage?.classList.add('is-netboot');
  const requests = new Set();
  const icons = window.DWRT_MENU_ICON || {};
  const writable = () => ['admin','owner'].includes(window.DWRT_SESSION?.tokens?.().role) && state.data.status?.supported===true && state.data.status?.capabilities?.management!==false && !state.errors.status;
  const dirtySettings = () => !!state.draft && JSON.stringify(state.draft) !== JSON.stringify(state.baseline);
  const dirtyEditor = () => state.editor && JSON.stringify(state.editor.draft) !== JSON.stringify(state.editor.baseline);
  const dirty = () => dirtySettings() || dirtyEditor();
  const button = (text, action, extra='', disabled=false) => `<button type="button" class="dwrt-kit-button" data-dwrt-component="button" data-nb-action="${action}" ${extra} ${disabled || state.busy ? 'disabled' : ''}>${escape(text)}</button>`;
  const field = (name, label, value, type='text', extra='') => `<label class="nb-field dwrt-kit-field"><span>${escape(label)}</span><input class="dwrt-kit-input" data-nb-field="${name}" name="${name}" type="${type}" value="${escape(value)}" ${extra} ${!writable() || state.busy ? 'disabled' : ''}></label>`;
  const checkbox = (name,label,checked,extra='') => `<label class="nb-check"><input type="checkbox" data-nb-field="${name}" ${checked?'checked':''} ${extra} ${!writable()||state.busy?'disabled':''}><span>${escape(label)}</span></label>`;
  const badge = (label, tone='muted') => ui.statusBadgeMarkup?.(label,tone,{dot:false}) || `<span>${escape(label)}</span>`;
  const selectedDefault = (id,arch) => {
    if(!id)return '跟随全局';
    const image=state.data.images?.items.find((i)=>i.id===id);
    return !image?'原指定已失效 · 返回菜单/本地':!image.enabled||image.image_status!=='ready'?`${image.name}（已失效 · 返回菜单/本地）`:arch&&image.arch&&arch!==image.arch?`${image.name}（架构不兼容 · 返回菜单/本地）`:image.name;
  };
  function defaultsOptions(current) {
    return `<option value="">跟随全局 / 返回菜单</option>${(state.data.images?.items||[]).map((i)=>`<option value="${escape(i.id)}" ${i.id===current?'selected':''} ${(!i.enabled||i.image_status!=='ready')&&i.id!==current?'disabled':''}>${escape(i.name)}${!i.enabled?'（已停用）':i.image_status!=='ready'?'（未就绪）':''}</option>`).join('')}${current&&!state.data.images?.items.some((i)=>i.id===current)?`<option value="${escape(current)}" selected>原指定已失效 · 返回菜单/本地</option>`:''}`;
  }
  async function request(path, method='GET', payload) {
    const controller = new AbortController(); requests.add(controller);
    try {
      const response = await (window.DWRT_REQUEST?.fetch || window.fetch.bind(window))(path.startsWith('/api/')?path:`/api/v1/netboot/${path}`, {method,signal:controller.signal,headers:payload?{'Content-Type':'application/json'}:{},body:payload?JSON.stringify(payload):undefined});
      const json = await response.json();
      if(!response.ok || (json.code!==undefined&&json.code!==2000) || json.ok===false || (json.data?.ok===false && path!=='preflight')) {
        const error = new Error(detail(json.data?.error || json.message || `HTTP ${response.status}`));
        error.payload=json;error.status=response.status;throw error;
      }
      return json.data || json;
    } finally { requests.delete(controller); }
  }
  function values(s) {const copy=clone(s);delete copy.revision;return copy;}
  async function load() {
    const seq=++state.seq;
    const names=['status','settings','interfaces','images','clients','logs'];
    const results=await Promise.allSettled(names.map((name)=>request(name==='logs'?`logs?offset=${state.logOffset}&limit=20`:name)));
    if(!state.mounted||seq!==state.seq)return;
    results.forEach((result,i)=>{
      const name=names[i];
      if(result.status==='fulfilled') {
        delete state.errors[name];state.data[name]=result.value;
        if(name==='settings') {
          state.revision=result.value.revision;
          if(!dirtySettings()){state.baseline=values(result.value);state.draft=clone(state.baseline);state.baselineRevision=result.value.revision;}
        }
      } else state.errors[name]=result.reason.status===404?'当前版本尚不支持内网启动':result.reason.message;
    });
    state.loading=false;render();
  }
  function eventsMarkup(items) {
    return items?.length?`<div class="nb-table-scroll dwrt-kit-table-scroll"><table class="dwrt-kit-table"><thead><tr><th>时间</th><th>事件</th><th>客户端</th><th>原因</th></tr></thead><tbody>${items.map((e)=>`<tr><td>${escape(time(e.time))}</td><td>${escape(detail(e.type))}</td><td>${escape(e.mac||'—')}</td><td>${escape(detail(e.reason))}</td></tr>`).join('')}</tbody></table></div>`:'<p class="nb-empty">暂无启动访问事件</p>';
  }
  function overview() {
    const s=state.data.status;if(!s)return '<p class="nb-empty">运行状态尚未读取</p>';
    return `<section class="nb-panel dwrt-kit-glass-surface" data-dwrt-surface="dense-surface"><div class="nb-toolbar"><h2>启动服务</h2>${button(s.configured_enabled?'停用':'启用','toggle','',!writable()||!state.baseline)}</div><div class="nb-summary"><div><span>运行状态</span><strong>${escape(detail(s.runtime_state))}</strong></div><div><span>配置开关</span><strong>${s.configured_enabled?'已启用':'已停用'}</strong></div><div><span>就绪镜像 / 登记镜像</span><strong>${s.ready_images??'—'} / ${s.image_count??'—'}</strong></div></div>
      ${(s.interfaces||[]).map((lan)=>`<div class="nb-row"><strong>${escape(lan.name||lan.id)}</strong><span>${escape(lan.ipv4||'无地址')} · ${escape(detail(lan.mode))}</span><span>HTTP：${escape(detail(lan.http))} / TFTP：${escape(detail(lan.tftp))}</span>${lan.url?`<code>${escape(lan.url)}</code>`:''}</div>`).join('')||'<p>尚未选择发布 LAN</p>'}${s.last_result&&s.last_result.applied!==true?`<p role="status">${escape(detail(s.last_result.error))} ${s.last_result.rollback_failed?'恢复失败':s.last_result.rolled_back?'已恢复之前的配置':''}</p>`:''}</section>
      <section class="nb-panel dwrt-kit-glass-surface" data-dwrt-surface="dense-surface"><h2>引导资源</h2>${(s.resources||[]).map((r)=>`<div class="nb-row"><strong>${escape(r.name)}</strong>${badge(r.ready?'可用':detail(r.reason),r.ready?'muted':'warning')}<span>${escape(r.version||'版本未登记')} · ${escape(r.license||'许可证未登记')}</span></div>`).join('')}<p class="nb-muted">RHEL 9 系 x86_64 HTTP 模板。启动文件就绪与客户机验证结果分别记录。</p></section>
      <section class="nb-panel dwrt-kit-glass-surface" data-dwrt-surface="dense-surface"><h2>最近访问</h2>${eventsMarkup(s.events?.items)}</section>`;
  }
  function images() {
    const items=state.data.images?.items||[];
    return `<section class="nb-panel dwrt-kit-glass-surface" data-dwrt-surface="dense-surface"><div class="nb-toolbar"><h2>镜像库</h2>${button('添加镜像','add-image','',!writable())}</div><p class="nb-muted">请先在文件管理器上传 ISO；移走原文件会使镜像不可用。</p>${items.length?`<div class="nb-images">${items.map((i,index)=>`<article class="nb-image"><div class="nb-toolbar"><h3>${escape(i.name)}</h3>${badge(detail(i.image_status),i.image_status==='ready'?'muted':'warning')}</div><p class="nb-path">${escape(i.path)}</p><div class="nb-metadata"><span>${escape([i.os,i.version,i.arch].filter(Boolean).join(' · ')||'尚未识别')}</span><span>${i.size_bytes?`${(i.size_bytes/1073741824).toFixed(2)} GiB`:'大小未读取'}</span><span>${i.enabled?'镜像已启用':'镜像已停用'}</span><span>${i.boot_verified?'客户机已验证':'客户机未验证'}</span></div>${i.error?`<p>${escape(detail(i.error))}</p>`:''}${i.global_default||i.client_references?`<p>默认引用：${i.global_default?'全局 ':''}${i.client_references||0} 个客户端；失效后返回菜单或本地。</p>`:''}<div class="nb-actions">${button('编辑','edit-image',`data-id="${escape(i.id)}"`,!writable())}${button('重识别','redetect',`data-id="${escape(i.id)}"`,!writable()||i.busy)}${button('重挂载','remount',`data-id="${escape(i.id)}"`,!writable()||i.busy)}${button('上移','up',`data-id="${escape(i.id)}"`,!writable()||index===0)}${button('下移','down',`data-id="${escape(i.id)}"`,!writable()||index===items.length-1)}${button('移除登记','remove-image',`data-id="${escape(i.id)}"`,!writable()||i.busy)}</div></article>`).join('')}</div>`:'<p class="nb-empty">尚未登记镜像</p>'}</section>`;
  }
  function clients() {
    const items=state.data.clients?.items||[];
    return `<section class="nb-panel dwrt-kit-glass-surface" data-dwrt-surface="dense-surface"><div class="nb-toolbar"><h2>客户端</h2>${button('添加客户端','add-client','',!writable())}</div>${items.length?`<div class="nb-table-scroll dwrt-kit-table-scroll"><table class="dwrt-kit-table"><thead><tr><th>名称 / MAC</th><th>授权</th><th>默认镜像</th><th>最近访问</th><th>操作</th></tr></thead><tbody>${items.map((c)=>`<tr><td><strong>${escape(c.name||'未命名')}</strong><br><code>${escape(c.mac)}</code><br>${escape(detail(c.source))}</td><td>${c.source==='observed'?(state.data.settings?.allow_unknown?'按未知客户端策略允许':'待允许'):c.allowed?'允许':'拒绝'}</td><td>${escape(selectedDefault(c.default_image_id,c.arch))}</td><td>${escape(time(c.last_seen))}<br>${escape(c.ip||'—')} · ${escape(c.arch||'—')} / ${escape(c.platform||'固件未报告')}</td><td>${button('编辑','edit-client',`data-id="${escape(c.id)}"`,!writable())}${c.source==='observed'?'':button('删除记录','remove-client',`data-id="${escape(c.id)}"`,!writable())}</td></tr>`).join('')}</tbody></table></div>`:'<p class="nb-empty">暂无客户端登记或访问记录</p>'}</section><section class="nb-panel dwrt-kit-glass-surface" data-dwrt-surface="dense-surface"><div class="nb-toolbar"><h2>访问事件</h2>${button('清空业务事件','clear-logs','',!writable())}</div>${eventsMarkup(state.data.logs?.items)}<div class="nb-toolbar"><span>${state.data.logs?`第 ${Math.min(state.logOffset+1,state.data.logs.total)}–${Math.min(state.logOffset+(state.data.logs.items?.length||0),state.data.logs.total)} 条，共 ${state.data.logs.total} 条`:'事件尚未读取'}</span><div class="nb-actions">${button('较新事件','logs-newer','',state.logOffset===0)}${button('更早事件','logs-older','',!state.data.logs||state.logOffset+20>=state.data.logs.total)}</div></div><p class="nb-muted">事件保留在内存，最多 256 条。最近访问不表示在线，脚本请求不表示启动成功。</p></section>`;
  }
  function settings() {
    const d=state.draft;if(!d)return '<p class="nb-empty">设置尚未读取，暂不可编辑。</p>';
    return `<section class="nb-panel dwrt-kit-glass-surface" data-dwrt-surface="dense-surface"><h2>发布范围</h2>${checkbox('enabled','启用内网启动',d.enabled)}<fieldset class="nb-lans"><legend>选择 LAN</legend>${(state.data.interfaces?.items||[]).map((lan)=>checkbox('interface_ids',`${lan.name} · ${lan.ipv4||'无地址'} · ${detail(lan.mode)}`,d.interface_ids.includes(lan.id),`value="${escape(lan.id)}"`)+(!lan.available?`<p class="nb-muted">${escape(detail(lan.reason))}</p>`:'')).join('')||'<p>没有可选 LAN</p>'}</fieldset><p class="nb-muted">当前仅支持单 LAN 的本机 DHCP 附加模式，保存前会检查发布范围和依赖。</p></section>
      <section class="nb-panel dwrt-kit-glass-surface" data-dwrt-surface="dense-surface"><h2>启动菜单与访问</h2><div class="nb-fields">${field('http_port','HTTP 端口',d.http_port,'number','min="1024" max="65535"')}${field('menu_timeout','菜单等待（秒，0 为一直等待）',d.menu_timeout,'number','min="0" max="600"')}<label class="nb-field dwrt-kit-field"><span>全局默认镜像</span><select class="dwrt-kit-input" data-nb-field="default_image_id" ${!writable()?'disabled':''}>${defaultsOptions(d.default_image_id)}</select></label>${field('menu_password',d.has_menu_password?'菜单密码（已设置，留空不变）':'菜单密码（未设置）',d.menu_password||'','password','autocomplete="new-password"')}</div>${checkbox('allow_unknown','允许未知客户端访问启动菜单',d.allow_unknown)}${d.has_menu_password?checkbox('clear_password','明确清除现有菜单密码',d.clear_password):''}<p class="nb-muted">MAC 用于启动策略识别；局域网 HTTP 不加密，会话有效期为 12 小时。这里的密码与管理员登录分开。</p>${button('预检草稿','preflight','',!writable())}</section>`;
  }
  function savebar() {
    root.querySelector('[data-nb-savebar]').innerHTML=ui.floatingSavebarMarkup?.({visible:!!dirty()&&writable(),busy:state.busy,saveLabel:state.editor?'保存':'预检并应用',message:'有未保存的更改'})||'';
    reserveEditorSpace();
  }
  function reserveEditorSpace() {
    const bar=root.querySelector('.dwrt-floating-savebar');
    root.style.setProperty('--nb-savebar-height',`${bar?.getBoundingClientRect().height||0}px`);
  }
  function render() {
    if(!state.mounted)return;
    const nav=[['overview','概览','dashboard'],['images','镜像库','storage_service'],['clients','客户端','terminal'],['settings','设置','system']];
    const active=document.activeElement?.dataset?.nbField;
    root.classList.add('nb-host');root.classList.toggle('nb-traditional',!desktop);
    root.innerHTML=`<div class="nb-workbench">${desktop?`<aside class="nb-sidebar dwrt-rail"><div class="dwrt-rail-brand"><img src="/static/images/logo-wide.png" alt="DreamingOS"></div><nav class="dwrt-rail-list" aria-label="内网启动">${nav.map(([id,label,icon])=>`<button class="dwrt-rail-item ${state.tab===id?'is-active':''}" type="button" data-nb-tab="${id}" title="${label}" aria-label="${label}" ${state.tab===id?'aria-current="page"':''}><span class="dwrt-rail-item-icon">${icons[icon]||icons.network_config||''}</span><span class="dwrt-rail-item-text"><span class="dwrt-rail-item-title">${label}</span></span></button>`).join('')}</nav></aside>`:''}<main class="nb-main">${!desktop?`<nav class="dwrt-kit-tabs dwrt-kit-page-tabs nb-tabs" aria-label="内网启动"><span class="dwrt-kit-tab-pill" aria-hidden="true"></span>${nav.map(([id,label])=>`<button type="button" class="dwrt-kit-tab ${state.tab===id?'is-active':''}" data-value="${id}" data-nb-tab="${id}" aria-selected="${state.tab===id}">${label}</button>`).join('')}</nav>`:''}<div class="nb-toolbar"><h1>${nav.find(([id])=>id===state.tab)[1]}</h1>${button('刷新','refresh')}</div>${state.loading?'<p role="status">正在读取内网启动配置…</p>':''}${Object.entries(state.errors).map(([key,error])=>`<p class="nb-message" role="alert">${escape(key)}：${escape(error)}</p>`).join('')}${state.notice?`<p class="nb-message" role="status">${escape(state.notice)}</p>`:''}${!['admin','owner'].includes(window.DWRT_SESSION?.tokens?.().role)?'<p class="nb-muted">当前账号仅可查看</p>':''}${({overview,images,clients,settings}[state.tab])()}</main></div><div data-nb-savebar></div><div data-nb-overlay></div>`;
    savebar();renderEditor();root.querySelector('.nb-workbench').inert=!!state.editor;ui.mountAll?.(root);if(active)root.querySelector(`[data-nb-field="${active}"]`)?.focus();
  }
  function renderEditor() {
    const e=state.editor;const overlay=root.querySelector('[data-nb-overlay]');if(!e){overlay.innerHTML='';return;}
    const d=e.draft,image=e.kind==='image';
    overlay.innerHTML=`<div class="dwrt-kit-modal-layer is-open nb-editor-layer"><section class="dwrt-kit-modal nb-editor" role="dialog" aria-modal="true" aria-labelledby="nb-editor-title"><div class="nb-toolbar"><h2 id="nb-editor-title">${e.id?'编辑':'添加'}${image?'镜像':'客户端'}</h2>${button('关闭','close-editor')}</div><div class="nb-editor-body">${state.notice?`<p role="alert" class="nb-message">${escape(state.notice)}</p>`:''}${field('name','名称',d.name||'')}${image?`${!e.id?field('path','服务器 ISO 路径',d.path||'')+button('浏览服务器文件','browse')+`<div data-nb-files>${e.files?filesMarkup(e.files):''}</div>`:`<p class="nb-path">${escape(d.path)}</p>`}${checkbox('enabled','启用此镜像',d.enabled)}${e.id?`<details><summary>识别出的启动模板</summary><p>${escape(d.method||'尚未支持')} · 客户机未验证</p><code>${escape(d.kernel)}</code><br><code>${escape(d.initrd)}</code><p>高级手工模板暂未开放。</p></details>`:''}`:`${field('mac','MAC 地址',d.mac||'','text',e.id?'readonly':'')}${checkbox('allowed','允许网络启动',d.allowed)}<label class="nb-field dwrt-kit-field"><span>默认镜像</span><select class="dwrt-kit-input" data-nb-field="default_image_id">${defaultsOptions(d.default_image_id)}</select></label>`}</div><div class="nb-actions">${button('取消','close-editor')}</div></section></div>`;
  }
  async function confirmation(title,description) {
    if(!ui.confirmationMarkup)return window.confirm(`${title}\n${description}`);
    return new Promise((resolve)=>{
      const layer=document.createElement('div');layer.innerHTML=ui.confirmationMarkup({title,description,tone:'warning'});root.append(layer);const before=document.activeElement;
      const finish=(yes)=>{layer.remove();state.confirmation=null;before?.focus();resolve(yes);};state.confirmation=()=>finish(false);
      layer.addEventListener('click',(event)=>{if(event.target.closest('[data-dwrt-confirm-accept]'))finish(true);else if(event.target.closest('[data-dwrt-confirm-cancel]'))finish(false);});
      layer.querySelector('[data-dwrt-confirm-cancel]')?.focus();
    });
  }
  function settingsPatch() {
    const patch={};for(const [key,value] of Object.entries(state.draft))if(!['has_menu_password','menu_password','clear_password'].includes(key)&&JSON.stringify(value)!==JSON.stringify(state.baseline[key]))patch[key]=clone(value);
    if(state.draft.clear_password)patch.menu_password='';else if(state.draft.menu_password)patch.menu_password=state.draft.menu_password;return patch;
  }
  function preflightDescription(p) {
    return `${p.enabled?'将在以下 LAN 附加启动信息并开放引导服务':'撤销内网启动发布'}：${p.interfaces.map((i)=>`${i.name} (${i.ipv4})`).join('、')||'无'}。HTTP 端口 ${p.http_port}。${p.errors.map((e)=>`${e.field}：${detail(e.code)}`).join('；')}`;
  }
  async function saveSettings(previewOnly=false) {
    if(state.baselineRevision!==state.revision) {
      if(!await confirmation('配置版本已变化','保留你的草稿，以服务器当前版本重新预检；应用前还会显示影响范围。'))return;
      const current=await request('settings');const patch=settingsPatch();state.baseline=values(current);state.baselineRevision=current.revision;state.draft={...clone(state.baseline),...patch,...(Object.hasOwn(patch,'menu_password')&&patch.menu_password===''?{clear_password:true}:{})};
    }
    const patch=settingsPatch(),payload={...patch,expected_revision:state.baselineRevision};
    const p=await request('preflight','POST',payload);
    if(previewOnly||!p.ok){state.notice=preflightDescription(p);render();return;}
    if(!await confirmation('应用内网启动配置',preflightDescription(p)))return;
    const result=await request('settings','PUT',{...payload,confirm:true,apply:true,preflight_token:p.fingerprint});
    const canonical=await request('settings');
    if(Object.entries(patch).some(([key,value])=>key==='menu_password'?canonical.has_menu_password!==!!value:JSON.stringify(canonical[key])!==JSON.stringify(value)))throw new Error('配置已写入，但回读与草稿不一致；草稿已保留。');
    state.data.settings=canonical;state.revision=canonical.revision;state.baseline=values(canonical);state.draft=clone(state.baseline);state.baselineRevision=canonical.revision;
    state.notice=result.applied?'配置已保存并应用':'配置已保存，运行状态待确认';await load();
  }
  async function saveEditor() {
    const e=state.editor;if(!e)return;let d=e.draft;
    if(e.revision!==state.revision) {
      if(!await confirmation('配置版本已变化','保留当前编辑内容，并以最新版本重试保存。'))return;
      const latest=await request(e.kind==='image'?'images':'clients');
      if(e.id) {
        const current=latest.items?.find((item)=>item.id===e.id);
        if(!current)throw new Error('该记录已被移除，草稿已保留。');
        const patch=Object.fromEntries(Object.entries(d).filter(([key,value])=>JSON.stringify(value)!==JSON.stringify(e.baseline[key])));
        e.baseline=clone(current);e.draft={...clone(current),...patch};d=e.draft;
      }
      e.revision=latest.revision;
    }
    const image=e.kind==='image';const fields=image?(e.id?['name','enabled']:['name','path','root_id','enabled']):['name','mac','allowed','default_image_id'];
    const payload={confirm:true,expected_revision:e.revision};fields.forEach((key)=>{if(d[key]!==undefined)payload[key]=d[key];});
    const collection=image?'images':'clients';
    const result=await request(`${collection}${e.id?`/${encodeURIComponent(e.id)}`:''}`,e.id?'PUT':'POST',payload);
    // Keep the receipt even if canonical GET fails, so retry updates this record.
    const returnedId=e.id||(image?result.image?.id:result.client?.id);
    if(returnedId){e.id=returnedId;e.revision=result.revision;state.revision=result.revision;}
    const canonical=await request(collection);
    const saved=canonical.items?.find((i)=>i.id===returnedId);
    if(!saved||saved.name!==d.name||(image&&saved.enabled!==d.enabled)||(!image&&(saved.allowed!==d.allowed||saved.default_image_id!==d.default_image_id)))throw new Error('回读未确认保存结果，草稿已保留。');
    state.editor=null;state.revision=result.revision;state.data[collection]=canonical;
    state.notice=image&&saved.image_status!=='ready'?`已登记镜像，${detail(saved.image_status)}：${detail(saved.error)}`:'已保存';await load();
  }
  async function browse(path='/',rootId='') {
    const data=await request(`/api/v1/storage/files?path=${encodeURIComponent(path)}&root_id=${encodeURIComponent(rootId)}`);
    if(!state.editor)return;const holder=root.querySelector('[data-nb-files]');if(!holder)return;
    state.editor.files=data;holder.innerHTML=filesMarkup(data);
  }
  function filesMarkup(data) {
    return `<div class="nb-file-browser"><p>${escape(data.path)}</p><div class="nb-actions">${(data.roots||[]).map((r)=>button(r.name||r.path,'browse-dir',`data-path="${escape(r.path)}" data-root="${escape(r.id)}"`)).join('')}${button('上级目录','browse-dir',`data-path="${escape(data.path.replace(/\/[^/]+\/?$/,'')||'/')}" data-root="${escape(data.root_id)}"`)}</div>${(data.entries||[]).filter((e)=>e.type==='directory'||e.is_dir||/\.iso$/i.test(e.name)).map((e)=>button(e.name,e.type==='directory'||e.is_dir?'browse-dir':'pick-file',`data-path="${escape(e.path)}" data-root="${escape(data.root_id)}"`)).join('')||'<p>没有目录或 ISO 文件</p>'}</div>`;
  }
  async function perform(action,node) {
    const id=node?.dataset.id;
    if(action==='refresh'){await load();return;}
    if(action==='logs-newer'||action==='logs-older'){state.logOffset=Math.max(0,state.logOffset+(action==='logs-older'?20:-20));await load();return;}
    if(action==='close-editor'){if(!dirtyEditor()||await confirmation('放弃编辑','未保存的镜像或客户端修改将被丢弃。')){state.editor=null;render();}return;}
    if(!writable())return;
    if(action.startsWith('add-')||action.startsWith('edit-')) {
      const kind=action.endsWith('image')?'image':'client';const data=id?clone(state.data[`${kind}s`].items.find((i)=>i.id===id)):(kind==='image'?{name:'',path:'',enabled:true}:{name:'',mac:'',allowed:false,default_image_id:''});
      state.editor={kind,id,revision:state.revision,baseline:clone(data),draft:data};render();root.querySelector('[role=dialog] input')?.focus();return;
    }
    if(action==='browse'||action==='browse-dir'){await browse(node.dataset.path,node.dataset.root);return;}
    if(action==='pick-file'){Object.assign(state.editor.draft,{path:node.dataset.path,root_id:node.dataset.root});renderEditor();savebar();return;}
    if(action==='toggle'){state.draft.enabled=!state.data.status.configured_enabled;state.tab='settings';render();return;}
    if(action==='preflight'){await saveSettings(true);return;}
    if(action==='save-editor'){await saveEditor();return;}
    if(action==='remove-image'||action==='remove-client'||action==='clear-logs'||action==='redetect'||action==='remount') {
      const image=state.data.images?.items.find((i)=>i.id===id);
      const text=action==='remove-image'?`移除“${image?.name}”的镜像登记，保留 ISO 文件。默认引用失效后返回菜单或本地。`:
        action==='remove-client'?'删除授权记录后，该客户端按未知客户端策略处理；这不等于永久封禁。':
        action==='clear-logs'?'仅清除此业务的内存访问事件，保留系统审计与客户端记录。':`将${action==='remount'?'重新挂载并识别':'重新识别'}“${image?.name}”；存在活跃传输时操作会被拒绝。`;
      if(!await confirmation('确认操作',text))return;
      const path=action==='clear-logs'?'logs':action==='remove-client'?`clients/${encodeURIComponent(id)}`:`images/${id}${['redetect','remount'].includes(action)?`/${action}`:''}`;
      const result=await request(path,['redetect','remount'].includes(action)?'POST':'DELETE',{confirm:true,expected_revision:state.revision});state.revision=result.revision??state.revision;
      if(action==='clear-logs')state.logOffset=0;
      state.notice=result.image&&result.image.image_status!=='ready'?detail(result.image.error):'操作已完成';await load();return;
    }
    if(action==='up'||action==='down') {
      const ids=state.data.images.items.map((i)=>i.id),index=ids.indexOf(id),next=index+(action==='up'?-1:1);if(next<0||next>=ids.length)return;
      [ids[index],ids[next]]=[ids[next],ids[index]];
      await request('images/order','PUT',{ids,expected_revision:state.revision,confirm:true});await load();
    }
  }
  async function onClick(event) {
    const tab=event.target.closest('[data-nb-tab]');if(tab&&!state.busy){state.tab=tab.dataset.nbTab;render();return;}
    const save=event.target.closest('[data-dwrt-savebar-save]'),discard=event.target.closest('[data-dwrt-savebar-discard]'),node=event.target.closest('[data-nb-action]');
    if(!save&&!discard&&!node||state.busy)return;
    if(discard){if(state.editor)state.editor.draft=clone(state.editor.baseline);else state.draft=clone(state.baseline);state.notice='';render();return;}
    state.seq++;state.busy=true;savebar();
    try{if(save)await(state.editor?saveEditor():saveSettings());else await perform(node.dataset.nbAction,node);}
    catch(error){if(error.name!=='AbortError'){state.notice=error.message;if(error.payload?.data?.result)state.notice+=` ${JSON.stringify(error.payload.data.result)}`;if(error.status===409)await load();}}
    finally{state.busy=false;if(state.mounted){render();}}
  }
  function onInput(event) {
    const input=event.target.closest('[data-nb-field]');if(!input||!writable()||state.busy)return;
    const d=state.editor?.draft||state.draft;if(!d)return;const key=input.dataset.nbField;const previous=JSON.stringify(d[key]);
    if(key==='interface_ids')d[key]=[...root.querySelectorAll('[data-nb-field="interface_ids"]:checked')].map((el)=>el.value);
    else d[key]=input.type==='checkbox'?input.checked:input.type==='number'?Number(input.value):input.value;
    // A blur change can repeat the input edit while a save button is pressed.
    // Keep that button in the DOM so its click reaches the handler.
    if(previous===JSON.stringify(d[key]))return;
    state.notice='';savebar();
  }
  function beforeUnload(event){if(dirty()||state.busy){event.preventDefault();event.returnValue='';}}
  let previousHash=location.hash;
  function beforeHash(event){if((dirty()||state.busy)&&!window.confirm('有未保存的内网启动更改，放弃并离开？')){history.replaceState(null,'',previousHash);event.stopImmediatePropagation();}else previousHash=location.hash;}
  function onKey(event) {
    const dialogs=root.querySelectorAll('[role=dialog]'),dialog=dialogs[dialogs.length-1];if(!dialog)return;
    if(event.key==='Escape'){event.preventDefault();if(state.confirmation)state.confirmation();else if(!state.busy)perform('close-editor');}
    if(event.key==='Tab'){const focus=[...dialog.querySelectorAll('button:not(:disabled),input:not(:disabled),select:not(:disabled),summary'),...(!state.confirmation?[...root.querySelectorAll('[data-nb-savebar] button:not(:disabled)')]:[])];if(!focus.length)return;const index=focus.indexOf(document.activeElement);if(event.shiftKey&&index<=0){event.preventDefault();focus.at(-1).focus();}else if(!event.shiftKey&&(index<0||index===focus.length-1)){event.preventDefault();focus[0].focus();}}
  }
  root.addEventListener('click',onClick);root.addEventListener('input',onInput);root.addEventListener('change',onInput);root.addEventListener('keydown',onKey);
  window.addEventListener('beforeunload',beforeUnload);window.addEventListener('hashchange',beforeHash,true);
  window.addEventListener('resize',reserveEditorSpace);
  render();load();
  const poll=setInterval(()=>{if(state.mounted&&!document.hidden&&!state.busy&&!state.editor&&!state.confirmation&&!dirtySettings()&&(!window.frameElement||window.frameElement.getClientRects().length))load();},5000);
  return {refresh:load,unmount(){state.mounted=false;state.seq++;clearInterval(poll);requests.forEach((c)=>c.abort());state.confirmation?.();root.removeEventListener('click',onClick);root.removeEventListener('input',onInput);root.removeEventListener('change',onInput);root.removeEventListener('keydown',onKey);window.removeEventListener('beforeunload',beforeUnload);window.removeEventListener('hashchange',beforeHash,true);window.removeEventListener('resize',reserveEditorSpace);ui.unmount?.(root);stage?.classList.remove('is-netboot');root.replaceChildren();root.style.removeProperty('--nb-savebar-height');root.classList.remove('nb-host','nb-traditional');}};
}
export default {mount,VERSION};
