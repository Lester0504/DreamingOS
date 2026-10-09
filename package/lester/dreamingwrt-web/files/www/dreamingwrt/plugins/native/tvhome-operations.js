import {createPackages} from './tvhome-packages.js?v=20261005-tvhome-host-01';
// Local TV operations shared by the traditional and desktop hosts.
export function createOperations(ctx) {
  const { request, render, root, ui, canWrite, escape: esc, activeTab } = ctx;
  const packages=createPackages(ctx);
  const A='/api/v1/tvhome';
  const clone=v=>JSON.parse(JSON.stringify(v));
  const same=(a,b)=>JSON.stringify(a)===JSON.stringify(b);
  const init=(method,body)=>({method,headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
  const req=(path,options)=>request('tvhome-operations',A+path,options);
  const get=(path)=>req(path);
  const views={assets:{},notice:{},events:{}};
  const state={notice:null,noticeDraft:null,storage:null,storageDraft:null,assets:[],roots:[],terminals:[],groups:[],commands:[],events:[],eventKind:'',eventTerminal:'',eventBefore:0,edit:null,file:null,uploadKind:'image',progress:'',preview:null,previewKind:'',command:{kind:'text',text:'',asset_id:'',minutes:5,target:{mode:'terminals',ids:[]}},busy:false,message:'',error:''};
  const urls=new Map();let mounted=true,uploadAbort=false;
  const btn=(label,action,value='',allowed=true)=>`<button type="button" class="dwrt-kit-btn" data-tv-op="${action}" data-value="${esc(value)}" ${!allowed||(state.busy&&action!=='cancel-upload')?'disabled':''}>${esc(label)}</button>`;
  const select=(field,value,options,disabled=false)=>`<select class="dwrt-kit-input" data-tv-op-field="${field}" ${disabled?'disabled':''}>${options.map(([v,l])=>`<option value="${esc(v)}" ${String(value??'')===String(v)?'selected':''}>${esc(l)}</option>`).join('')}</select>`;
  const field=(name,input)=>`<label>${esc(name)}${input}</label>`;
  const input=(key,value,type='text',extra='')=>`<input class="dwrt-kit-input" type="${type}" data-tv-op-field="${key}" value="${esc(value??'')}" ${extra} ${canWrite()?'':'disabled'}>`;
  const panel=(title,body,actions='')=>`<section class="tvhome-panel dwrt-kit-glass-surface"><div class="tvhome-panel-head"><h2>${title}</h2><div class="tvhome-record-actions">${actions}</div></div>${body}</section>`;
  const table=(heads,rows,empty)=>`<div class="tvhome-table-wrap"><table class="tvhome-table"><thead><tr>${heads.map(h=>`<th>${h}</th>`).join('')}</tr></thead><tbody>${rows||`<tr><td colspan="${heads.length}">${empty}</td></tr>`}</tbody></table></div>`;
  const time=n=>n?new Date(n).toLocaleString():'—';
  const bytes=n=>`${(Number(n)/1024/1024).toFixed(1)} MiB`;
  const error=e=>{const code=e?.payload?.error?.code||e?.payload?.code;const map={asset_in_use:'素材仍被引用，请查看占用者后再删除。',revision_conflict:'配置已被其他窗口修改，草稿已保留。',missing_asset:'引用的素材不存在或上传未完成。',storage_not_configured:'请先选择存放素材的数据盘。',storage_unavailable:'数据盘暂不可用。',invalid_asset_format:'文件实际格式与所选类型不匹配。',upload_incomplete:'上传尚未完整，不能发布素材。',no_targets:'当前范围没有终端。',invalid_target:'请选择明确且有效的终端或分组。'};return map[code]||e?.message||'请求失败';};
  const redraw=()=>{if(mounted)render();};
  function dirty() {return packages.dirty()||!!(state.notice&&state.noticeDraft&&!same(state.notice,state.noticeDraft))||!!(state.storage&&state.storageDraft&&!same(state.storage,state.storageDraft))||!!(state.edit&&!same(state.edit.baseline,state.edit.draft));}
  function savebar() {return ui.floatingSavebarMarkup({visible:dirty(),busy:state.busy,disabled:!dirty()||!canWrite(),saveLabel:'保存',discardLabel:'撤销',message:state.error||'配置有未保存更改。'});}
  const feedback=()=>`${state.error?`<p role="alert" class="tvhome-op-error">${esc(state.error)}</p>`:''}${state.message?`<p role="status">${esc(state.message)}</p>`:''}`;
  async function load(tab,force=false) {
    if(packages.owns(tab))return packages.load(tab,force);
    if(!views[tab]||views[tab].loading||(!force&&views[tab].loaded))return;
    views[tab].loading=true;views[tab].error='';redraw();
    try {
      if(tab==='assets') {
        const [library,storage,roots]=await Promise.all([get('/assets'),get('/assets/storage'),request('tvhome-storage-roots','/api/v1/storage/files?path=%2F').catch(()=>null)]);
        if(!mounted)return;state.assets=library.assets||[];
        if(!state.storageDraft||same(state.storage,state.storageDraft)){state.storage=storage;state.storageDraft=clone(storage);}
        state.roots=(roots?.roots||roots?.data?.roots||[]).filter(r=>!r.read_only);
      } else if(tab==='notice') {
        const [notice,commands,terminals,groups,assets]=await Promise.all([get('/notice'),get('/commands'),get('/terminals'),get('/groups'),get('/assets')]);
        if(!mounted)return;if(!state.noticeDraft||same(state.notice,state.noticeDraft)){state.notice=notice;state.noticeDraft=clone(notice);}
        state.commands=commands.commands||[];state.terminals=terminals.terminals||[];state.groups=groups.groups||[];state.assets=assets.assets||[];
      } else {
        const query=new URLSearchParams({kind:state.eventKind,terminal_id:state.eventTerminal,limit:'100'});if(state.eventBefore){query.set('before_ms',state.eventBefore);query.set('before_id',state.eventBeforeId||0);}
        const [events,terminals]=await Promise.all([get('/events?'+query),get('/terminals')]);if(!mounted)return;
        state.events=state.eventBefore?[...state.events,...(events.events||[])]:events.events||[];state.nextBefore=events.next_before_ms;state.nextBeforeId=events.next_before_id;state.terminals=terminals.terminals||[];
      }
      views[tab].loaded=true;
    } catch(e){views[tab].error=error(e);}finally{views[tab].loading=false;redraw();}
  }
  function targetEditor(target,prefix) {
    const options=target.mode==='groups'?state.groups:state.terminals;
    return `<div class="tvhome-record-grid">${field('目标范围',select(prefix+'.mode',target.mode,[['terminals','指定终端'],['groups','指定分组'],['all','全部终端']],!canWrite()))}
      ${target.mode==='all'?'<p>将覆盖全部终端，包括当前离线终端。</p>':`<fieldset class="tvhome-op-targets"><legend>选择${target.mode==='groups'?'分组':'终端'}</legend>${options.map(t=>`<label><input type="checkbox" data-tv-op-target="${prefix}" value="${esc(t.id)}" ${target.ids.includes(t.id)?'checked':''} ${canWrite()?'':'disabled'}>${esc(t.name||t.id)}</label>`).join('')||'<p>暂无可选目标</p>'}</fieldset>`}</div>`;
  }
  function renderAssets() {
    const storage=state.storageDraft||{},edit=state.edit;
    const limits=state.storage||{};
    const storagePanel=panel('素材存储',`<div class="tvhome-record-grid">${field('数据盘',select('storage.root_id',storage.root_id,[['','选择数据盘'],...state.roots.map(r=>[r.id,r.label||r.path||r.id])],!canWrite()||state.assets.length>0))}${field('盘内目录',input('storage.path',storage.path||'', 'text','placeholder="已存在的相对目录，可留空使用根目录"'))}</div><p class="tvhome-note">图片上限 ${bytes(limits.max_image_bytes||0)}，视频上限 ${bytes(limits.max_video_bytes||0)}，素材库配额 ${bytes(limits.quota_bytes||0)}。</p>`);
    const upload=panel('上传素材',`<div class="tvhome-record-grid">${field('文件','<input type="file" data-tv-op-file accept="image/png,image/jpeg,image/gif,image/webp,video/mp4,video/webm" '+(canWrite()?'':'disabled')+'>')}${field('类型',select('uploadKind',state.uploadKind,[['image','图片'],['video','视频'],['icon','图标'],['logo','标志']],!canWrite()))}</div><p>${esc(state.file?.name||'尚未选择文件')}</p><p role="status" data-tv-op-progress>${esc(state.progress)}</p>`,btn('开始上传','upload','',canWrite()&&!!state.file&&!!state.storage?.configured)+btn('取消上传','cancel-upload','',!!state.progress));
    const rows=state.assets.map(a=>`<tr><td><b>${esc(a.name)}</b><small class="tvhome-record-sub">${esc(a.mime||a.kind)} · ${bytes(a.size)}</small></td><td>${a.state==='ready'?'可用':`上传中 ${bytes(a.received)} / ${bytes(a.size)}`}</td><td>${(a.references||[]).length?`<details><summary>${a.references.length} 处引用</summary><ul>${a.references.map(r=>`<li>${esc(r.type)} / ${esc(r.id)} · ${esc(r.field)}</li>`).join('')}</ul></details>`:'未引用'}</td><td><div class="tvhome-record-actions">${btn('预览','preview',a.id,a.state==='ready')}${btn('编辑','edit-asset',a.id,canWrite())}${btn('删除','delete-asset',a.id,canWrite())}</div></td></tr>`).join('');
    return feedback()+storagePanel+upload+panel('素材库',table(['素材','状态','占用者','操作'],rows,'暂无素材'))+
      (edit?panel('编辑素材',`<div class="tvhome-record-grid">${field('名称',input('asset.name',edit.draft.name))}${field('类型',select('asset.kind',edit.draft.kind,edit.draft.kind==='video'?[['video','视频']]:[['image','图片'],['icon','图标'],['logo','标志']],!canWrite()))}</div>`,btn('关闭编辑','close-asset')):'')+
      (state.preview?panel('素材预览',state.previewKind==='video'?`<video controls src="${esc(state.preview)}" class="tvhome-op-preview"></video>`:`<img src="${esc(state.preview)}" class="tvhome-op-preview" alt="素材预览">`,btn('关闭预览','close-preview')):'')+`<div data-tv-ops-savebar>${savebar()}</div>`;
  }
  function renderNotice() {
    const notice=state.noticeDraft;if(!notice)return '';
    const command=state.command;
    const localDate=n=>n?new Date(n-new Date(n).getTimezoneOffset()*60000).toISOString().slice(0,16):'';
    const noticePanel=panel('本机电视公告',`<div class="tvhome-record-grid">${field('启用',`<input type="checkbox" data-tv-op-field="notice.enabled" ${notice.enabled?'checked':''} ${canWrite()?'':'disabled'}>`)}${field('滚动速度',input('notice.speed',notice.speed,'number','min="10" max="200"'))}${field('开始时间',input('notice.start_at_ms',localDate(notice.start_at_ms),'datetime-local'))}${field('结束时间',input('notice.end_at_ms',localDate(notice.end_at_ms),'datetime-local'))}</div>${field('公告文字',`<textarea class="dwrt-kit-input" rows="3" maxlength="2000" data-tv-op-field="notice.text" ${canWrite()?'':'disabled'}>${esc(notice.text)}</textarea>`)}${targetEditor(notice.target,'notice.target')}<p class="tvhome-note">本机跑马灯与云平台公告独立。当前保存版本 ${esc(state.notice.revision)}；终端展示证据可在事件中查看。</p>`);
    const assets=state.assets.filter(a=>a.state==='ready'&&(command.kind==='video'?a.kind==='video':a.kind!=='video'));
    const emergencyPanel=panel('应急覆盖',`<div class="tvhome-record-grid">${field('内容类型',select('command.kind',command.kind,[['text','文字'],['image','图片'],['video','视频']],!canWrite()))}${field('持续分钟',input('command.minutes',command.minutes,'number','min="1" max="1440"'))}</div>${command.kind==='text'?field('应急文字',`<textarea class="dwrt-kit-input" rows="3" maxlength="4000" data-tv-op-field="command.text" ${canWrite()?'':'disabled'}>${esc(command.text)}</textarea>`):field('选择素材',select('command.asset_id',command.asset_id,[['','选择已上传素材'],...assets.map(a=>[a.id,a.name])],!canWrite()))}${targetEditor(command.target,'command.target')}`,btn('发送应急','send-command','emergency',canWrite())+btn('刷新所选终端配置','send-command','refresh',canWrite()));
    const application={unknown:'等待回执',displayed:'已展示',applied:'已应用',stopped:'已停止',failed:'执行失败'},delivery={pending:'待送达',received:'已接收'};
    const commands=state.commands.map(c=>`<tr><td>${c.type==='emergency'?'应急覆盖':'刷新配置'}<small class="tvhome-record-sub">${esc(c.command_id)}</small></td><td>${esc(({active:'有效',stopped:'已停止',expired:'已到期'})[c.state]||c.state)}<small class="tvhome-record-sub">${time(c.expires_at_ms)}</small></td><td><details><summary>${c.results?.length||0} 个目标</summary>${(c.results||[]).map(r=>`<p>${esc(state.terminals.find(t=>t.id===r.terminal_id)?.name||r.terminal_id)}：${delivery[r.delivery]||esc(r.delivery)} · ${application[r.application]||esc(r.application)}${r.reason==='offline'?' · 心跳离线':''}</p>`).join('')}</details></td><td>${btn('停止','stop-command',c.command_id,canWrite()&&c.state==='active')}</td></tr>`).join('');
    return feedback()+noticePanel+emergencyPanel+panel('命令与终端结果',table(['命令','状态 / 到期','逐终端结果','操作'],commands,'暂无命令'),btn('刷新结果','reload-commands'))+`<div data-tv-ops-savebar>${savebar()}</div>`;
  }
  function renderEvents() {
    const kinds=['crash','anr','playerError','playerFallback','lowSpec','install','upgrade','log','login','configApplied','noticeDisplayed'];
    const filters=`<div class="tvhome-record-grid">${field('终端',select('eventTerminal',state.eventTerminal,[['','全部终端'],...state.terminals.map(t=>[t.id,t.name||t.id])]))}${field('事件类型',select('eventKind',state.eventKind,[['','全部类型'],...kinds.map(k=>[k,k])]))}</div>`;
    return feedback()+panel('事件与诊断',filters+table(['时间','终端','类型','详情'],state.events.map(ev=>`<tr><td>${time(ev.time_ms)}</td><td>${esc(state.terminals.find(t=>t.id===ev.terminal_id)?.name||ev.terminal_id)}</td><td>${esc(ev.kind)}</td><td><details><summary>查看详情</summary><pre class="tvhome-json">${esc(JSON.stringify(ev,null,2))}</pre></details></td></tr>`).join(''),'暂无符合条件的事件'),btn('查询','query-events')+btn('加载更早事件','more-events','',state.events.length>=100));
  }
  async function action(fn) {state.error='';state.message='';state.busy=true;redraw();try{await fn();}catch(e){state.error=error(e);}finally{state.busy=false;redraw();}}
  async function save() {
    if(packages.owns(activeTab()))return packages.save();
    if(!canWrite())return;
    await action(async()=>{
      if(state.storage&&state.storageDraft&&!same(state.storage,state.storageDraft)){
        const sent={root_id:state.storageDraft.root_id,path:state.storageDraft.path||''};await req('/assets/storage',init('PUT',sent));const actual=await get('/assets/storage');if(actual.root_id!==sent.root_id||actual.path!==sent.path)throw Error('素材存储回读不一致，草稿已保留。');state.storage=actual;state.storageDraft=clone(actual);
      }
      if(state.edit&&!same(state.edit.baseline,state.edit.draft)){
        const sent=clone(state.edit.draft);await req('/assets/'+state.edit.id,init('PUT',sent));const actual=await get('/assets/'+state.edit.id);if(actual.name!==sent.name||actual.kind!==sent.kind)throw Error('素材信息回读不一致。');state.edit={id:actual.id,baseline:{name:actual.name,kind:actual.kind},draft:{name:actual.name,kind:actual.kind}};await load('assets',true);
      }
      if(state.notice&&state.noticeDraft&&!same(state.notice,state.noticeDraft)){
        const sent=clone(state.noticeDraft);delete sent.revision;sent.expected_revision=state.notice.revision;await req('/notice',init('PUT',sent));const actual=await get('/notice');delete sent.expected_revision;const compare=clone(actual);delete compare.revision;if(!same(sent,compare))throw Error('公告回读不一致，草稿已保留。');state.notice=actual;state.noticeDraft=clone(actual);
      }
      state.message='配置已保存并回读，终端结果以回执为准。';
    });
  }
  async function upload() {
    const file=state.file;if(!file||!canWrite())return;
    uploadAbort=false;await action(async()=>{
      const limit=state.uploadKind==='video'?state.storage.max_video_bytes:state.storage.max_image_bytes;if(file.size>limit)throw Error(`文件超过 ${bytes(limit)} 上限。`);
      const a=await req('/assets',init('POST',{name:file.name,kind:state.uploadKind,size:file.size}));
      try {
        let offset=0;while(offset<file.size){if(uploadAbort||!mounted)throw Error('上传已取消。');const chunk=await file.slice(offset,offset+state.storage.chunk_bytes).arrayBuffer();
          const result=await req('/assets/'+a.id+'/content?offset='+offset,{method:'PUT',headers:{'Content-Type':'application/octet-stream'},body:chunk});offset=result.received;state.progress=`正在上传 ${Math.round(offset/file.size*100)}%`;const el=root.querySelector('[data-tv-op-progress]');if(el)el.textContent=state.progress;
        }
        await req('/assets/'+a.id+'/complete',init('POST',{}));state.file=null;state.progress='上传完成，素材已通过校验。';await load('assets',true);
      }catch(e){await req('/assets/'+a.id,{method:'DELETE'}).catch(()=>{});throw e;}
    });
  }
  async function sendCommand(type) {
    if(!canWrite())return;const draft=state.command,target=draft.target;
    const count=state.terminals.filter(t=>target.mode==='all'||(target.mode==='groups'?target.ids.includes(t.group_id):target.ids.includes(t.id))).length;
    if(!count){state.error='请选择至少一个实际终端。';redraw();return;}
    if(!window.confirm(`将${type==='emergency'?'发送应急覆盖':'刷新配置'}到 ${count} 个终端，范围：${target.mode==='all'?'全部终端':'当前明确选择'}。是否继续？`))return;
    await action(async()=>{await req('/commands',init('POST',{type,target:clone(target),expires_at_ms:Date.now()+Number(draft.minutes)*60000,payload:type==='refresh'?{}:draft.kind==='text'?{kind:'text',text:draft.text}:{kind:draft.kind,asset_id:draft.asset_id}}));state.commands=(await get('/commands')).commands||[];state.message='命令已保存；请查看逐终端接收与执行结果。';});
  }
  function handleClick(event) {
    if(packages.handleClick(event))return true;
    const button=event.target.closest('[data-tv-op]');if(!button)return false;
    const actionName=button.dataset.tvOp,id=button.dataset.value;if(button.disabled)return true;
    if(actionName==='cancel-upload'){uploadAbort=true;return true;}
    if(actionName==='upload'){upload();return true;}
    if(actionName==='edit-asset'){const a=state.assets.find(x=>x.id===id);if(state.edit&&!same(state.edit.baseline,state.edit.draft)&&!window.confirm('放弃素材编辑草稿？'))return true;state.edit={id,baseline:{name:a.name,kind:a.kind},draft:{name:a.name,kind:a.kind}};redraw();return true;}
    if(actionName==='close-asset'){if(!state.edit||same(state.edit.baseline,state.edit.draft)||window.confirm('放弃素材编辑草稿？'))state.edit=null;redraw();return true;}
    if(actionName==='delete-asset'){if(canWrite()&&window.confirm('删除这份素材？有引用的素材会被服务器拒绝。'))action(async()=>{await req('/assets/'+id,{method:'DELETE'});await load('assets',true);});return true;}
    if(actionName==='preview'){action(async()=>{if(!window.DWRT_REQUEST?.fetch)throw Error('当前宿主未提供授权素材读取。');const response=await window.DWRT_REQUEST.fetch(A+'/assets/'+id+'/content');if(!response.ok)throw Error('素材读取失败：'+response.status);if(urls.has(id))URL.revokeObjectURL(urls.get(id));const url=URL.createObjectURL(await response.blob());urls.set(id,url);state.preview=url;state.previewKind=state.assets.find(a=>a.id===id)?.kind;});return true;}
    if(actionName==='close-preview'){state.preview=null;redraw();return true;}
    if(actionName==='send-command'){sendCommand(id);return true;}
    if(actionName==='stop-command'){if(canWrite()&&window.confirm('停止该命令对原目标终端的应急覆盖？'))action(async()=>{await req('/commands/'+id+'/stop',init('POST',{}));state.commands=(await get('/commands')).commands||[];});return true;}
    if(actionName==='reload-commands'){action(async()=>{state.commands=(await get('/commands')).commands||[];});return true;}
    if(actionName==='query-events'||actionName==='more-events'){state.eventBefore=actionName==='more-events'?state.nextBefore:0;state.eventBeforeId=actionName==='more-events'?state.nextBeforeId:0;load('events',true);return true;}
    return true;
  }
  function handleInput(event) {
    if(packages.handleInput(event))return true;
    const wasDirty=dirty();const el=event.target;if(el.matches('[data-tv-op-file]')){state.file=el.files?.[0]||null;state.progress='';redraw();return true;}
    if(el.matches('[data-tv-op-target]')){const target=el.dataset.tvOpTarget==='notice.target'?state.noticeDraft.target:state.command.target;target.ids=el.checked?[...new Set([...target.ids,el.value])]:target.ids.filter(id=>id!==el.value);const host=root.querySelector('[data-tv-ops-savebar]');if(host)host.innerHTML=savebar();return true;}
    const path=el.dataset.tvOpField;if(!path)return false;
    let value=el.type==='checkbox'?el.checked:el.type==='number'?Number(el.value):el.type==='datetime-local'?(el.value?new Date(el.value).getTime():0):el.value;
    const keys=path.split('.');let owner=keys[0]==='notice'?state.noticeDraft:keys[0]==='command'?state.command:keys[0]==='storage'?state.storageDraft:keys[0]==='asset'?state.edit.draft:state;
    if(keys.length===3){owner=owner[keys[1]];owner[keys[2]]=value;if(keys[2]==='mode')owner.ids=[];}else owner[keys.at(-1)]=value;
    if(el.tagName==='SELECT'||el.type==='checkbox')redraw();else if(wasDirty!==dirty()){const host=root.querySelector('[data-tv-ops-savebar]');if(host)host.innerHTML=savebar();}
    return true;
  }
  return {load,dirty,save,handleClick,handleInput,owns:tab=>!!views[tab]||packages.owns(tab),
    discard(){if(packages.owns(activeTab()))return packages.discard();if(state.notice)state.noticeDraft=clone(state.notice);if(state.storage)state.storageDraft=clone(state.storage);if(state.edit)state.edit.draft=clone(state.edit.baseline);state.error='';state.message='';redraw();},
    render(tab){if(packages.owns(tab))return packages.render(tab);const view=views[tab];if(view?.error)return panel('加载失败',`<p role="alert">${esc(view.error)}</p>`);if(!view?.loaded)return panel('正在加载','<p role="status">读取本机配置…</p>');return tab==='assets'?renderAssets():tab==='notice'?renderNotice():renderEvents();},
    destroy(){packages.destroy();mounted=false;uploadAbort=true;urls.forEach(url=>URL.revokeObjectURL(url));urls.clear();}
  };
}
