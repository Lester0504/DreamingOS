const VERSION = '20261002-support-02';
const API = '/api/v1/support';
const esc = value => String(value ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const statusLabel = { pending:'待处理', processing:'处理中', resolved:'已解决', closed:'已关闭' };
const deliveryLabel = { queued:'已保存，等待投递', submitting:'正在投递', submitted:'云端已接收', failed:'投递失败', deleted:'云端工单已删除' };
const syncMessage = code => ({service_unavailable:'云服务暂不可达，将自动重试',cloud_unavailable:'云服务暂不可达，将自动重试',ticket_closed:'工单已关闭，请联系支持人员重开',revision_conflict:'工单已更新，请刷新后重新提交',invalid_image:'图片未通过校验',device_authentication_failed:'设备认证失败，请检查设备时间及云服务配置',payload_too_large:'内容超出服务限制'}[code] || '暂未收到有效回执，请稍后刷新；内容已保留');
const date = value => { const d = new Date(value); return Number.isNaN(d.getTime()) ? '时间未提供' : d.toLocaleString('zh-CN', { hour12:false }); };
const requestId = () => 'req-' + (crypto.randomUUID?.() || Date.now().toString(36) + Math.random().toString(36).slice(2));
const field = (label, input) => `<label class="dwrt-kit-field" data-dwrt-component="field"><span>${label}</span>${input}</label>`;
const button = (action, label, extra='') => `<button type="button" class="dwrt-kit-button" data-dwrt-component="button" data-feedback-action="${action}" ${extra}>${label}</button>`;

export function mount(context={}) {
  const root=context.root, kit=window.DWRT_UI_KIT || context.ui, host=context.host || 'traditional';
  if (!root) return {unmount(){}};
  const originalClass=root.className, owner='feedback-'+requestId(), controller=new AbortController();
  const s={alive:true,caps:null,list:null,detail:null,filter:'',page:1,busy:false,error:'',sheet:null,images:new Map(),refreshing:false,replyKey:null,replyBody:null};
  root.classList.add('feedback-route');
  if (!document.querySelector('link[data-feedback-style]')) {
    const link=document.createElement('link');link.rel='stylesheet';link.href='/static/desktop/bug-feedback/bug-feedback.css?v='+VERSION;link.dataset.feedbackStyle='';document.head.append(link);
  }
  const paint=node=>kit?.mountAll?.(node || root);
  async function api(path, method='GET', body) {
    const response=await (window.DWRT_REQUEST?.fetch || window.fetch.bind(window))(API+path, {method,credentials:'same-origin',cache:'no-store',signal:controller.signal,
      headers:{Accept:'application/json',...(body ? {'Content-Type':'application/json'} : {})},...(body ? {body:JSON.stringify(body)} : {})});
    let payload;
    try { payload=await response.json(); } catch { const e=new Error(`服务返回了无效内容（HTTP ${response.status}）`);e.status=response.status;throw e; }
    if (!response.ok || payload.ok===false) {
      const code=payload.error?.code || payload.error_code;
      const message=response.status===401 ? '登录已过期，请完成重新登录；当前窗口中的草稿已保留。' : response.status===403 ? (payload.error?.message || '当前账号没有此操作权限') :
        response.status===404 ? '反馈或服务入口不存在' : response.status===429 ? `请求过于频繁，请在 ${response.headers.get('Retry-After') || '稍后'} 秒后重试` : payload.error?.message || payload.message || `请求失败（HTTP ${response.status}）`;
      const error=new Error(message);error.status=response.status;error.code=code;throw error;
    }
    return { data:payload.data, status:response.status };
  }
  function shown() {
    if (document.hidden || !document.hasFocus()) return false;
    try {
      if (parent!==window && parent.DWRT_DESKTOP_HOST) {
        const frame=window.frameElement, record=frame?.closest('.desktop-window');
        return Boolean(record && !record.hidden && record.classList.contains('is-active') && getComputedStyle(record).display!=='none');
      }
    } catch { return false; }
    return true;
  }
  async function setRecord(id, replace=false) {
    if(await navigate(id)===false)return;
    const url=new URL(location.href); if (id) url.searchParams.set('feedback_id', id); else url.searchParams.delete('feedback_id');
    history[replace?'replaceState':'pushState'](null,'',url);
  }
  function shell() {
    root.innerHTML=`<section class="feedback-app ${host!=='desktop'?'dwrt-kit-page-surface dwrt-kit-glass-surface':''}" data-host="${host}" aria-label="Bug反馈"><header class="feedback-toolbar"><h1>我的反馈</h1><div class="feedback-toolbar-actions">${button('refresh','刷新')}${button('new','新建反馈','disabled')}</div></header><p class="feedback-notice" role="status"></p><section class="feedback-list-view"><div class="feedback-filter">${field('状态',`<select class="dwrt-kit-select" data-feedback-filter><option value="">全部状态</option>${Object.entries(statusLabel).map(([v,l])=>`<option value="${v}">${l}</option>`).join('')}</select>`)}<span class="feedback-total"></span></div><div class="feedback-list" aria-live="polite">正在读取反馈…</div><footer class="feedback-pagination">${button('previous','上一页','disabled')}<span data-feedback-page></span>${button('next','下一页','disabled')}</footer></section><section class="feedback-detail-view" hidden><div class="feedback-detail-toolbar">${button('back','返回列表')}<span data-feedback-record></span></div><div class="feedback-detail-scroll" tabindex="0" aria-label="反馈详情"><div data-feedback-detail></div></div><form class="feedback-reply">${field('追加回复','<textarea class="dwrt-kit-textarea" name="reply" rows="2" aria-label="追加回复" placeholder="补充复现步骤、发生时间或处理结果"></textarea>')}<div class="feedback-reply-foot"><span data-feedback-reply-hint></span><button class="dwrt-kit-button" data-dwrt-component="button" type="submit">发送回复</button></div></form></section></section>`;
    paint();
  }
  function notice(message) { if(s.alive)root.querySelector('.feedback-notice').textContent=message || ''; }
  function drawList() {
    if(!s.list)return;
    const list=root.querySelector('.feedback-list');
    list.innerHTML=s.list.items.length ? s.list.items.map(item=>`<button type="button" class="feedback-row" data-feedback-record-id="${esc(item.id)}"><span class="feedback-row-main"><span class="feedback-row-module">${esc(item.module_name)}${item.unread ? `<span class="feedback-unread">${item.unread} 条新回复</span>` : ''}</span><span class="feedback-row-description">${esc(item.description)}</span><span class="feedback-row-meta">${esc(item.cloud_ticket_id || item.id)} · ${date(item.updated_at)}</span></span><span class="feedback-row-state">${esc(statusLabel[item.status] || deliveryLabel[item.delivery_state] || '状态待确认')}<small>${esc(deliveryLabel[item.delivery_state] || '')}</small></span></button>`).join('') : `<div class="feedback-empty"><strong>${s.filter?'没有符合筛选条件的反馈':'还没有反馈记录'}</strong><p>${s.filter?'更换状态后重试。':'提交遇到的问题后，可在这里查看处理进度和回复。'}</p></div>`;
    root.querySelector('.feedback-total').textContent=`${s.list.total} 条反馈`;
    root.querySelector('[data-feedback-page]').textContent=`第 ${s.page} 页`;
    root.querySelector('[data-feedback-action=previous]').disabled=s.page<=1;
    root.querySelector('[data-feedback-action=next]').disabled=s.page*s.list.page_size>=s.list.total;
    paint(list);
  }
  async function imageURL(ticket, attachment) {
    const key=ticket.id+'/'+attachment.id;
    if(s.images.has(key))return s.images.get(key);
    const {data}=await api(`/tickets/${encodeURIComponent(ticket.id)}/attachments/${encodeURIComponent(attachment.id)}`);
    const bytes=Uint8Array.from(atob(data.data),c=>c.charCodeAt(0));
    const url=URL.createObjectURL(new Blob([bytes],{type:'image/png'}));
    if(!s.alive){URL.revokeObjectURL(url);return '';}
    s.images.set(key,url);return url;
  }
  function releaseImages(){for(const url of s.images.values())URL.revokeObjectURL(url);s.images.clear();}
  async function drawDetail() {
    const d=s.detail;if(!d)return;
    const container=root.querySelector('[data-feedback-detail]'),scroll=root.querySelector('.feedback-detail-scroll');const top=scroll.scrollTop;
    container.innerHTML=`<div class="feedback-record-status"><span class="feedback-status">${esc(statusLabel[d.status] || deliveryLabel[d.delivery_state] || '状态待确认')}</span><span>${esc(deliveryLabel[d.delivery_state] || '')}</span>${d.sync_error?`<span class="feedback-error">同步暂未完成：${esc(syncMessage(d.sync_error))}</span>`:''}</div><h2>${esc(d.module_name)}</h2><p class="feedback-prose">${esc(d.description)}</p><dl class="feedback-metadata"><dt>提交人</dt><dd>${esc(d.reporter_name)}</dd>${d.reporter_contact?`<dt>联系方式</dt><dd>${esc(d.reporter_contact)}</dd>`:''}<dt>提交时间</dt><dd>${date(d.created_at)}</dd></dl>${d.attachments?.length?`<div class="feedback-attachments">${d.attachments.map(a=>`<button type="button" data-feedback-image="${esc(a.id)}" class="feedback-image"><img alt="${esc(a.name)}" loading="lazy"><span>${esc(a.name)}</span></button>`).join('')}</div>`:''}${d.system_info?`<details class="feedback-diagnostic-detail"><summary>已提交的诊断信息</summary><pre>${esc(pretty(d.system_info))}</pre></details>`:''}${d.resolution?`<section class="feedback-resolution"><h3>处理结论</h3><p class="feedback-prose">${esc(d.resolution)}</p></section>`:''}<section class="feedback-comments" aria-label="往来回复"><h3>往来回复</h3>${d.comments?.length?d.comments.map(c=>`<article class="feedback-comment" data-comment-id="${esc(c.id)}"><header><strong>${c.author_kind==='admin'?'支持人员 · ':''}${esc(c.author_name)}</strong><time>${date(c.created_at)}</time></header><p class="feedback-prose">${esc(c.content)}</p></article>`).join(''):'<p class="feedback-muted">暂时没有回复</p>'}${(d.pending_comments||[]).map(c=>`<article class="feedback-comment is-pending"><header><strong>${esc(deliveryLabel[c.delivery_state] || '待投递')}</strong></header><p class="feedback-prose">${esc(c.content)}</p>${c.error?`<p class="feedback-error">${esc(syncMessage(c.error))}。原内容仍保留在此。</p>`:''}</article>`).join('')}</section>`;
    root.querySelector('[data-feedback-record]').textContent=d.cloud_ticket_id || d.id;
    const form=root.querySelector('.feedback-reply'), allowed=d.permissions?.reply===true && s.caps?.reply===true;
    form.hidden=d.deleted===true;
    form.querySelector('textarea').disabled=!allowed || s.busy;
    form.querySelector('button').disabled=!allowed || s.busy;
    root.querySelector('[data-feedback-reply-hint]').textContent=d.status==='closed'?'工单已关闭，需支持人员重新打开后才能回复。':!d.cloud_ticket_id?'投递完成后可以追加回复。':!allowed?'当前账号仅可查看。':'Enter 发送，Shift+Enter 换行';
    scroll.scrollTop=top;paint(container);
    for(const a of d.attachments || []) {
      try {const url=await imageURL(d,a);if(s.detail?.id===d.id){const img=container.querySelector(`[data-feedback-image="${CSS.escape(a.id)}"] img`);if(img)img.src=url;}}
      catch(error){const img=container.querySelector(`[data-feedback-image="${CSS.escape(a.id)}"] img`);if(img)img.alt=`图片暂不可用：${error.message}`;}
    }
    markRead();
  }
  function pretty(value){try{return JSON.stringify(JSON.parse(value),null,2);}catch{return value;}}
  let reading=false;
  async function markRead() {
    if(reading || !s.detail || s.sheet || !shown() || !s.caps?.mark_read)return;
    const comments=[...root.querySelectorAll('[data-comment-id]')],view=root.querySelector('.feedback-detail-scroll').getBoundingClientRect();
    const visible=comments.filter(node=>{const r=node.getBoundingClientRect();return r.bottom>view.top && r.bottom<=view.bottom;});
    const cursor=visible.at(-1)?.dataset.commentId;
    if(!cursor || cursor===s.detail.last_read_comment_id)return;
    reading=true;
    try {const {data}=await api(`/tickets/${s.detail.id}/read`,'POST',{last_comment_id:cursor});if(s.detail?.id===data.id)s.detail.last_read_comment_id=data.last_read_comment_id;}
    catch(error){notice(error.message);} finally {reading=false;}
  }
  async function refresh() {
    if(s.refreshing || !s.alive)return;s.refreshing=true;const refreshingID=s.detail?.id;
    try {
      if(!s.caps){s.caps=(await api('/capabilities')).data;root.querySelector('[data-feedback-action=new]').disabled=!s.caps.submit;}
      if(s.detail){
        const current=s.detail.id,{data}=await api('/tickets/'+encodeURIComponent(current));
        if(s.detail?.id===current && !s.sheet && (getSelection()?.isCollapsed!==false)){s.detail=data;await drawDetail();}
      } else {
        const query=new URLSearchParams({page:String(s.page),page_size:'20',...(s.filter?{status:s.filter}:{})});
        s.list=(await api('/tickets?'+query)).data;drawList();
      }
      notice(s.caps.reason || '');
    } catch(error){if(s.alive){notice(error.message);if(!s.list&&!s.detail)root.querySelector('.feedback-list').textContent='暂时无法读取反馈。请点击刷新重试。';}}
    finally{s.refreshing=false;if(s.alive && refreshingID!==s.detail?.id)refresh();}
  }
  async function navigate(id) {
    if(s.sheet && !await closeSheet())return false;
    const reply=root.querySelector('[name=reply]');
    if(reply.value && s.detail?.id!==id && !await confirm('放弃尚未发送的回复？','回复还没有提交。'))return false;
    reply.value='';s.replyKey=null;s.replyBody=null;releaseImages();
    root.querySelector('.feedback-list-view').hidden=Boolean(id);root.querySelector('.feedback-detail-view').hidden=!id;
    if(!id){s.detail=null;root.querySelector('.feedback-toolbar h1').textContent='我的反馈';refresh();return;}
    s.detail={id};root.querySelector('.feedback-toolbar h1').textContent='反馈详情';root.querySelector('[data-feedback-detail]').textContent='正在读取详情…';
    await refresh();
  }
  const confirmations=new Set();
  async function confirm(title,description) {
    const node=document.createElement('div');node.dataset.feedbackOwner=owner;
    node.innerHTML=kit.confirmationMarkup({id:owner+'-confirm',tone:'warning',title,description,confirmLabel:'放弃'});document.body.append(node);
    return new Promise(resolve=>{const previous=document.activeElement;const done=value=>{document.removeEventListener('keydown',onKey,true);node.remove();confirmations.delete(done);previous?.focus();resolve(value);};const onKey=e=>{if(e.key==='Escape'){e.preventDefault();e.stopImmediatePropagation();done(false);}};confirmations.add(done);document.addEventListener('keydown',onKey,true);node.addEventListener('click',e=>{if(e.target.closest('[data-dwrt-confirm-accept]'))done(true);else if(e.target.closest('[data-dwrt-confirm-cancel]'))done(false);});node.querySelector('[data-dwrt-confirm-cancel]').focus();});
  }
  function draftState(){
    if(!s.sheet)return null;
    const el=s.sheet.element;
    return {request_id:s.sheet.requestId,module_id:el.querySelector('[name=module_id]').value,description:el.querySelector('[name=description]').value,
      reporter_name:el.querySelector('[name=reporter_name]').value,reporter_contact:el.querySelector('[name=reporter_contact]').value,
      attachments:s.sheet.files.map(({name,data,mime_type})=>({name,data,mime_type})),diagnostics:el.querySelector('[name=include_diagnostics]')?.checked?s.sheet.diagnostics:null};
  }
  function persistDraft(){
    if(!s.sheet || !s.caps?.subject)return;
    try{sessionStorage.setItem('dwrt.feedback.draft:'+s.caps.subject,JSON.stringify({draft:draftState(),submitted:s.sheet.submitted}));}
    catch{s.sheet.element.querySelector('[data-feedback-form-message]').textContent='草稿保留在当前窗口中；关闭浏览器前请提交。';}
  }
  async function closeSheet(force=false,preserve=false){
    if(!s.sheet)return true;if(s.busy&&!force)return false;
    if(!force&&s.sheet.dirty&&!await confirm('放弃这份反馈草稿？','问题描述与尚未提交的图片将被丢弃。'))return false;
    for(const file of s.sheet.files)URL.revokeObjectURL(file.url);
    const sheet=s.sheet;s.sheet=null;sheet.host.append(sheet.element,sheet.overlay);kit?.unmount?.(sheet.host);sheet.host.remove();
    if(s.caps?.subject&&!preserve)sessionStorage.removeItem('dwrt.feedback.draft:'+s.caps.subject);
    return true;
  }
  async function newFeedback(){
    if(!s.caps?.submit || !await closeSheet())return;
    const node=document.createElement('div');node.dataset.feedbackOwner=owner;
    node.innerHTML=`<button class="dwrt-kit-sheet-overlay is-open" data-feedback-owner="${owner}" data-feedback-action="close-sheet" aria-label="关闭"></button><aside class="dwrt-kit-sheet feedback-sheet is-open" data-feedback-owner="${owner}" data-dwrt-component="sheet" data-dwrt-sheet-size="form" aria-label="新建反馈"><header class="dwrt-kit-sheet-header"><strong>新建反馈</strong>${button('close-sheet','关闭')}</header><div class="dwrt-kit-sheet-body"><form class="feedback-form"><p class="feedback-muted">说明如何复现、期望结果与实际表现，有助于定位问题。</p>${field('问题模块',`<select class="dwrt-kit-select" name="module_id" required><option value="">请选择模块</option>${s.caps.modules.map(m=>`<option value="${esc(m.id)}">${esc(m.label)}</option>`).join('')}</select>`)}${field('问题描述',`<textarea class="dwrt-kit-textarea" name="description" rows="6" required placeholder="复现步骤：&#10;期望结果：&#10;实际表现："></textarea>`)}<span class="feedback-muted" data-feedback-length>至少 ${s.caps.limits.description_min} 个字符</span><div class="feedback-form-row">${field('显示名','<input class="dwrt-kit-input" name="reporter_name" maxlength="80" required autocomplete="name">')}${field('联系方式（可选）','<input class="dwrt-kit-input" name="reporter_contact" maxlength="200" autocomplete="off">')}</div><section class="feedback-upload" data-feedback-drop><strong>问题截图</strong><p class="feedback-muted">最多 ${s.caps.limits.attachments_max} 张静态 PNG，每张不超过 ${s.caps.limits.attachment_bytes/1024} KiB，总量不超过 ${s.caps.limits.attachments_total_bytes/1048576} MiB。</p><label class="dwrt-kit-button feedback-file-button" data-dwrt-component="button">选择图片<input type="file" accept="image/png" multiple data-feedback-files></label><span class="feedback-muted">也可拖入或粘贴</span><div class="feedback-previews"></div></section><section class="feedback-diagnostics"><label class="feedback-checkbox"><input type="checkbox" name="include_diagnostics" disabled>附带下方已确认的诊断信息</label>${button('diagnostics','查看诊断信息')}<div data-feedback-diagnostics></div></section><p class="feedback-error" data-feedback-form-message role="alert"></p></form></div><footer class="dwrt-kit-sheet-footer">${button('submit','提交反馈')}</footer></aside>`;
    document.body.append(node);const element=node.querySelector('aside'),overlay=node.querySelector('.dwrt-kit-sheet-overlay');
    s.sheet={host:node,element,overlay,files:[],diagnostics:null,dirty:false,requestId:requestId(),submitted:null};paint(node);
    let saved=null;try{saved=JSON.parse(sessionStorage.getItem('dwrt.feedback.draft:'+s.caps.subject)||'null');}catch{}
    if(saved?.draft){
      for(const key of ['module_id','description','reporter_name','reporter_contact'])element.querySelector(`[name=${key}]`).value=saved.draft[key]||'';
      s.sheet.requestId=saved.draft.request_id || s.sheet.requestId;s.sheet.submitted=saved.submitted;s.sheet.dirty=true;
      s.sheet.files=(saved.draft.attachments||[]).map(file=>({...file,size:atob(file.data).length,url:URL.createObjectURL(new Blob([Uint8Array.from(atob(file.data),c=>c.charCodeAt(0))],{type:'image/png'}))}));
      if(saved.draft.diagnostics){s.sheet.diagnostics=saved.draft.diagnostics;showDiagnostics();element.querySelector('[name=include_diagnostics]').checked=true;}
      previewFiles();lockSubmitted();
    }
    element.querySelector('[name=module_id]').focus();
  }
  function lockSubmitted(){
    if(!s.sheet)return;const locked=Boolean(s.sheet.submitted);
    for(const input of s.sheet.element.querySelectorAll('input,textarea,select'))input.disabled=locked || (input.name==='include_diagnostics'&&!s.sheet.diagnostics);
    s.sheet.element.querySelector('[data-feedback-action=submit]').textContent=locked?'重试原提交':'提交反馈';
  }
  function showDiagnostics(){
    const d=s.sheet?.diagnostics;if(!d)return;
    s.sheet.element.querySelector('[data-feedback-diagnostics]').innerHTML=`<dl class="feedback-metadata"><dt>固件版本</dt><dd>${esc(d.firmware_version || '未提供')}</dd><dt>设备型号</dt><dd>${esc(d.board || '未提供')}</dd><dt>架构</dt><dd>${esc(d.architecture || '未提供')}</dd><dt>运行时间</dt><dd>${d.uptime_seconds} 秒</dd></dl>`;
    const checkbox=s.sheet.element.querySelector('[name=include_diagnostics]');checkbox.disabled=false;
  }
  function previewFiles(){
    if(!s.sheet)return;
    s.sheet.element.querySelector('.feedback-previews').innerHTML=s.sheet.files.map((file,i)=>`<div class="feedback-preview"><img src="${file.url}" alt="${esc(file.name)}"><span>${esc(file.name)}</span>${button('remove-image','移除',`data-index="${i}" ${s.sheet.submitted?'disabled':''}`)}</div>`).join('');paint(s.sheet.element);
  }
  async function addFiles(files){
    const sheet=s.sheet;if(!sheet||sheet.submitted)return;const errors=[];
    for(const file of files){
      if(sheet.files.length>=s.caps.limits.attachments_max){errors.push(`${file.name}：最多选择5张图片`);continue;}
      if(file.type!=='image/png'){errors.push(`${file.name}：仅支持静态 PNG`);continue;}
      if(file.size>s.caps.limits.attachment_bytes || sheet.files.reduce((n,f)=>n+f.size,0)+file.size>s.caps.limits.attachments_total_bytes){errors.push(`${file.name}：图片大小超出限制`);continue;}
      try {
        const data=await new Promise((resolve,reject)=>{const r=new FileReader();r.onload=()=>resolve(String(r.result).split(',')[1]);r.onerror=reject;r.readAsDataURL(file);});
        if(s.sheet!==sheet)return;
        sheet.files.push({name:file.name,mime_type:'image/png',data,size:file.size,url:URL.createObjectURL(file)});sheet.dirty=true;
      } catch{errors.push(`${file.name}：读取失败`);}
    }
    if(s.sheet===sheet){previewFiles();sheet.element.querySelector('[data-feedback-form-message]').textContent=errors.join('；');persistDraft();}
  }
  async function submit(){
    const sheet=s.sheet;if(!sheet||s.busy)return;
    const form=sheet.element.querySelector('form');if(!sheet.submitted&&!form.reportValidity())return;
    const body=sheet.submitted || draftState();
    if([...body.description.trim()].length<s.caps.limits.description_min || [...body.description.trim()].length>s.caps.limits.description_max){sheet.element.querySelector('[data-feedback-form-message]').textContent=`问题描述须为 ${s.caps.limits.description_min}–${s.caps.limits.description_max} 个字符。`;return;}
    sheet.submitted=body;persistDraft();lockSubmitted();s.busy=true;sheet.element.querySelector('[data-feedback-action=submit]').disabled=true;
    try {
      const {data}=await api('/tickets','POST',body);s.busy=false;sheet.dirty=false;await closeSheet(true);setRecord(data.id);
      notice(data.delivery_state==='submitted'?'云端已接收这份反馈。':'反馈已保存在设备，正在等待云端接收。');
    } catch(error){
      if(s.sheet===sheet){sheet.element.querySelector('[data-feedback-form-message]').textContent=error.message;
        if(error.status && error.status<500 && ![401,408,409,429].includes(error.status))sheet.submitted=null;
        lockSubmitted();persistDraft();}
    } finally{s.busy=false;if(s.sheet===sheet)sheet.element.querySelector('[data-feedback-action=submit]').disabled=false;}
  }
  async function reply(event){
    event.preventDefault();if(s.busy || !s.detail?.permissions?.reply || !s.caps?.reply)return;
    const input=root.querySelector('[name=reply]'),content=input.value.trim();
    if(!content || [...content].length>s.caps.limits.comment_max){notice(`回复须为1–${s.caps.limits.comment_max}个字符。`);return;}
    s.replyKey ||= requestId();s.replyBody ||= {request_id:s.replyKey,expected_revision:s.detail.revision,content};s.busy=true;input.disabled=true;
    try{const {data}=await api('/tickets/'+s.detail.id+'/comments','POST',s.replyBody);input.value='';s.replyKey=null;s.replyBody=null;s.detail=data;await drawDetail();}
    catch(error){notice(error.message);if(error.status && error.status<500 && ![401,408,429].includes(error.status)){s.replyKey=null;s.replyBody=null;}}
    finally{s.busy=false;input.disabled=!s.detail.permissions.reply;root.querySelector('.feedback-reply button').disabled=!s.detail.permissions.reply;}
  }
  async function click(event){
    const target=event.target.closest('[data-feedback-action],[data-feedback-record-id],[data-feedback-image]');if(!target)return;
    if(!root.contains(target)&&target.closest('[data-feedback-owner]')?.dataset.feedbackOwner!==owner)return;
    try {
      if(target.dataset.feedbackRecordId){setRecord(target.dataset.feedbackRecordId);return;}
      if(target.dataset.feedbackImage){
        const a=s.detail.attachments.find(a=>a.id===target.dataset.feedbackImage),url=await imageURL(s.detail,a),dialog=document.createElement('dialog');
        dialog.className='feedback-lightbox';dialog.innerHTML=`<header><strong>${esc(a.name)}</strong><button class="dwrt-kit-button">关闭</button></header><img src="${url}" alt="${esc(a.name)}">`;root.append(dialog);dialog.querySelector('button').onclick=()=>dialog.close();dialog.addEventListener('close',()=>dialog.remove(),{once:true});dialog.showModal();return;
      }
      const action=target.dataset.feedbackAction;
      if(action==='new')await newFeedback();if(action==='back')setRecord(null);if(action==='refresh')await refresh();
      if(action==='previous' && s.page>1){--s.page;await refresh();}if(action==='next'){++s.page;await refresh();}
      if(action==='close-sheet'){event.preventDefault();event.stopImmediatePropagation();await closeSheet();}
      if(action==='submit')await submit();
      if(action==='diagnostics'&&s.sheet&&!s.sheet.submitted){const current=s.sheet;const {data}=await api('/diagnostics');if(s.sheet===current){s.sheet.diagnostics=data;showDiagnostics();s.sheet.element.querySelector('[name=include_diagnostics]').checked=false;}}
      if(action==='remove-image'&&s.sheet&&!s.sheet.submitted){const [file]=s.sheet.files.splice(Number(target.dataset.index),1);if(file)URL.revokeObjectURL(file.url);s.sheet.dirty=true;previewFiles();persistDraft();}
    }catch(error){notice(error.message);if(s.sheet)s.sheet.element.querySelector('[data-feedback-form-message]').textContent=error.message;}
  }
  function input(event){
    if(s.sheet?.element.contains(event.target)){s.sheet.dirty=true;const value=s.sheet.element.querySelector('[name=description]').value;s.sheet.element.querySelector('[data-feedback-length]').textContent=`${[...value.trim()].length} / ${s.caps.limits.description_max} 个字符`;persistDraft();}
  }
  function change(event){
    if(event.target.matches('[data-feedback-filter]')){s.filter=event.target.value;s.page=1;refresh();}
    if(event.target.matches('[data-feedback-files]')){addFiles(event.target.files);event.target.value='';}
  }
  function paste(event){if(s.sheet?.element.contains(event.target)&&event.clipboardData?.files.length){event.preventDefault();addFiles(event.clipboardData.files);}}
  function drag(event){if(s.sheet?.element.contains(event.target)&&event.dataTransfer?.types.includes('Files'))event.preventDefault();}
  function drop(event){if(s.sheet?.element.contains(event.target)&&event.dataTransfer?.files.length){event.preventDefault();addFiles(event.dataTransfer.files);}}
  function key(event){if(event.target===root.querySelector('[name=reply]')&&event.key==='Enter'&&!event.shiftKey&&!event.isComposing&&event.keyCode!==229)reply(event);}
  function leave(event){if(s.sheet?.dirty || root.querySelector('[name=reply]')?.value){persistDraft();event.preventDefault();event.returnValue='';}}
  function historyChange(){const id=new URL(location.href).searchParams.get('feedback_id');if(id!==s.detail?.id)navigate(id);}
  shell();root.querySelector('.feedback-reply').addEventListener('submit',reply);root.querySelector('.feedback-detail-scroll').addEventListener('scroll',markRead);
  document.addEventListener('click',click,true);document.addEventListener('input',input);document.addEventListener('change',change);document.addEventListener('paste',paste);document.addEventListener('dragover',drag);document.addEventListener('drop',drop);document.addEventListener('keydown',key);
  window.addEventListener('beforeunload',leave);window.addEventListener('popstate',historyChange);window.addEventListener('focus',markRead);document.addEventListener('visibilitychange',markRead);
  const timer=setInterval(()=>{if(!document.hidden&&!s.sheet&&!s.busy)refresh();},10000);
  const initial=new URL(location.href).searchParams.get('feedback_id');if(initial)navigate(initial);else refresh();
  window.addEventListener('pagehide',unmount);
  function unmount(){if(!s.alive)return;window.removeEventListener('pagehide',unmount);s.alive=false;controller.abort();clearInterval(timer);for(const done of confirmations)done(false);persistDraft();if(s.sheet){s.sheet.dirty=false;closeSheet(true,true);}releaseImages();
    document.removeEventListener('click',click,true);document.removeEventListener('input',input);document.removeEventListener('change',change);document.removeEventListener('paste',paste);document.removeEventListener('dragover',drag);document.removeEventListener('drop',drop);document.removeEventListener('keydown',key);
    window.removeEventListener('beforeunload',leave);window.removeEventListener('popstate',historyChange);window.removeEventListener('focus',markRead);document.removeEventListener('visibilitychange',markRead);root.replaceChildren();root.className=originalClass;}
  return {refresh,unmount};
}
