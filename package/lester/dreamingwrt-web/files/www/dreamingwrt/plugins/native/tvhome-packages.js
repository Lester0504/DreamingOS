// TV APK library and local rollout policy; dist owns TVHome releases.
export function createPackages(ctx) {
  const {request,render,root,ui,canWrite,escape:esc}=ctx;
  const A='/api/v1/tvhome',clone=v=>JSON.parse(JSON.stringify(v));
  const stable=v=>Array.isArray(v)?v.map(stable):v&&typeof v==='object'?Object.fromEntries(Object.keys(v).sort().map(k=>[k,stable(v[k])])):v;
  const same=(a,b)=>JSON.stringify(stable(a))===JSON.stringify(stable(b));
  const req=(path,opts)=>request('tvhome-packages',A+path,opts);
  const json=(method,body)=>({method,headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
  let alive=true,cancelled=false;
  const state={loaded:false,loading:false,error:'',message:'',busy:false,packages:[],terminals:[],groups:[],verifier:false,file:null,progress:'',edit:null,channel:'stable',source:undefined};
  const redraw=()=>{if(alive)render();};
  const dirty=()=>!!state.edit&&!same(state.edit.baseline,state.edit.draft);
  const btn=(text,action,id='',enabled=true)=>`<button type="button" class="dwrt-kit-btn" data-tv-pkg="${action}" data-id="${esc(id)}" ${!enabled||state.busy?'disabled':''}>${esc(text)}</button>`;
  const field=(label,control)=>`<label>${esc(label)}${control}</label>`;
  const input=(key,value,type='text')=>`<input class="dwrt-kit-input" type="${type}" data-tv-pkg-field="${key}" value="${esc(value??'')}" ${canWrite()?'':'disabled'}>`;
  const select=(key,value,options)=>`<select class="dwrt-kit-input" data-tv-pkg-field="${key}" ${canWrite()?'':'disabled'}>${options.map(([id,label])=>`<option value="${esc(id)}" ${id===value?'selected':''}>${esc(label)}</option>`).join('')}</select>`;
  const check=(key,value,label)=>field(label,`<input type="checkbox" data-tv-pkg-field="${key}" ${value?'checked':''} ${canWrite()?'':'disabled'}>`);
  const panel=(title,body,actions='')=>`<section class="tvhome-panel dwrt-kit-glass-surface"><div class="tvhome-panel-head"><h2>${esc(title)}</h2><div class="tvhome-record-actions">${actions}</div></div>${body}</section>`;
  const size=n=>`${(Number(n)/1048576).toFixed(1)} MiB`;
  const error=e=>({revision_conflict:'投放策略已被其他窗口修改，草稿已保留。',apk_verifier_unavailable:'APK 校验组件暂不可用。',apk_verification_failed:'APK 签名、包内容或发布源校验失败。',self_upgrade_requires_dist:'TV 桌面自身升级请从 TV 发布渠道导入。',release_unavailable:'该 TV 渠道暂无已发布版本。',package_version_exists:'同一包名与版本已存在，不能覆盖已验证文件。',package_enabled:'请先暂停投放，再删除 APK。',storage_not_configured:'请先在素材库选择数据盘。',invalid_target:'请选择明确的终端或分组。'})[e?.payload?.error?.code||e?.payload?.code]||e?.message||'请求失败';
  const stages={queued:'排队中',downloading:'下载中',downloaded:'已下载',awaiting_install:'等待安装',installer_launched:'已打开安装器',cancelled:'已取消',failed:'失败',installed:'已安装',started:'已启动'};
  const savebar=()=>ui.floatingSavebarMarkup({visible:dirty(),busy:state.busy,disabled:!dirty()||!canWrite(),saveLabel:'保存',discardLabel:'撤销',message:state.error||'投放策略有未保存更改。'});
  async function load(tab,force=false) {
    if(state.loading||(!force&&state.loaded))return;
    state.loading=true;state.error='';redraw();
    try{const [library,terminals,groups]=await Promise.all([req('/packages'),req('/terminals'),req('/groups')]);if(!alive)return;state.packages=library.packages||[];state.verifier=library.verifier_available;state.max=library.max_apk_bytes;state.chunk=library.chunk_bytes;state.terminals=terminals.terminals||[];state.groups=groups.groups||[];state.loaded=true;}
    catch(e){state.error=error(e);}finally{state.loading=false;redraw();}
  }
  async function action(fn){state.error='';state.message='';state.busy=true;redraw();try{await fn();}catch(e){state.error=error(e);}finally{state.busy=false;redraw();}}
  function editMarkup(kind) {
    const edit=state.edit;if(!edit||edit.kind!==kind)return '';
    const p=edit.draft,t=p.target,targets=t.mode==='groups'?state.groups:state.terminals;
    return panel('投放策略',`<p>${esc(edit.name)}</p><div class="tvhome-record-grid">${check('enabled',p.enabled,'启用投放')}${check('forced',p.forced,'要求更新')}${check('recommended',p.recommended,'推荐')}${field('分类',input('category',p.category))}${field('最低起始版本号',input('min_version_code',p.min_version_code,'number'))}${field('目标范围',select('target.mode',t.mode,[['terminals','指定终端'],['groups','指定分组'],['all','全部终端']]))}</div>${t.mode==='all'?'<p>覆盖全部电视；兼容与版本条件仍会逐台检查。</p>':`<fieldset class="tvhome-op-targets"><legend>选择${t.mode==='groups'?'分组':'终端'}</legend>${targets.map(v=>`<label><input type="checkbox" data-tv-pkg-target value="${esc(v.id)}" ${t.ids.includes(v.id)?'checked':''} ${canWrite()?'':'disabled'}>${esc(v.name||v.id)}</label>`).join('')||'<p>暂无可选目标</p>'}</fieldset>`}<p class="tvhome-note">最低起始版本号限制旧版本能否接收此包。“要求更新”仍通过电视上的系统安装器确认。</p>`,btn('关闭编辑','close-edit'));
  }
  function markup(tab) {
    const kind=tab==='upgrade'?'release':'app';
    const feedback=`${state.error?`<p role="alert" class="tvhome-op-error">${esc(state.error)}</p>`:''}${state.message?`<p role="status">${esc(state.message)}</p>`:''}`;
    if(!state.loaded)return feedback+panel(state.loading?'正在加载':'APK 列表不可用',state.loading?'<p role="status">读取 APK 与投放策略…</p>':'',btn('重试','reload'));
    let controls;
    if(kind==='app')controls=panel('上传 Android APK',`<p>${state.verifier?`单个 APK 上限 ${size(state.max)}。`:'APK 校验组件暂不可用。'}</p>${field('APK 文件',`<input type="file" accept=".apk,application/vnd.android.package-archive" data-tv-pkg-file ${canWrite()&&state.verifier?'':'disabled'}>`)}<p>${esc(state.file?.name||'尚未选择文件')}</p><p role="status" data-tv-pkg-progress>${esc(state.progress)}</p>`,btn('上传并校验','upload','',canWrite()&&state.verifier&&!!state.file));
    else controls=panel('TV 发布渠道',`<div class="tvhome-record-grid">${field('渠道',select('channel',state.channel,[['stable','稳定版'],['beta','测试版']]))}</div>${state.source===undefined?'<p>查询当前 TV 渠道的已发布版本。</p>':state.source?`<p>${esc(state.source.version)} · ${esc(state.source.id)} · ${size(state.source.size)}</p><p class="tvhome-note">${esc(state.source.changelog||'')} ${state.source.min_version?'低于 '+esc(state.source.min_version)+' 的版本要求更新。':''}</p>`:'<p>该 TV 渠道暂无已发布版本。</p>'}`,btn('查询发布源','source','',state.verifier)+btn('导入此渠道版本','import','',canWrite()&&state.verifier&&!!state.source));
    const rows=state.packages.filter(p=>p.kind===kind).map(p=>{
      const m=p.metadata||{},policy=p.policy||{},target=policy.target||{};
      const targets=target.mode==='all'?'全部终端':`${target.mode==='groups'?'分组':'终端'} ${(target.ids||[]).length} 个`;
      return `<tr><td><b>${esc(m.label||p.name)}</b><small class="tvhome-record-sub">${esc(m.package_name||'等待校验')}<br>${esc(m.version_name||'')} ${m.version_code?'('+esc(m.version_code)+')':''} · ${size(p.size)}</small><details><summary>包信息</summary><p>最低 SDK ${esc(m.min_sdk??'—')} · ${esc(m.no_native_code?'无原生库':(m.supported_abis||[]).join(', '))}</p><pre class="tvhome-json">${esc(JSON.stringify({sha256:m.sha256,signer_sha256:m.signer_sha256,source:p.source},null,2))}</pre></details></td><td>${p.state==='ready'?(policy.enabled?'投放中':'已暂停'):p.state==='importing'?'正在导入':`上传未完成 ${size(p.received)}`}<small class="tvhome-record-sub">${esc(targets)}</small></td><td>${p.results?.length?`<details><summary>${p.results.length} 台终端回执</summary>${p.results.map(r=>`<p>${esc(state.terminals.find(t=>t.id===r.terminal_id)?.name||r.terminal_id)}：${esc(stages[r.stage]||r.stage)}${r.actual?' · 实际版本 '+esc(r.actual.version_code):''}${r.detail?' · '+esc(r.detail):''}</p>`).join('')}</details>`:'尚无安装回执'}</td><td><div class="tvhome-record-actions">${btn('投放策略','edit',p.id,canWrite()&&p.state==='ready')}${btn('删除','delete',p.id,canWrite()&&!policy.enabled&&p.state!=='importing')}</div></td></tr>`;
    }).join('');
    return feedback+controls+panel(kind==='app'?'TV 应用':'TV 桌面升级',`<div class="tvhome-table-wrap"><table class="tvhome-table"><thead><tr><th>APK</th><th>投放</th><th>安装结果</th><th>操作</th></tr></thead><tbody>${rows||'<tr><td colspan="4">暂无 APK</td></tr>'}</tbody></table></div>`,btn('刷新结果','reload'))+editMarkup(kind)+`<div data-tv-pkg-savebar>${savebar()}</div>`;
  }
  async function save(){if(!canWrite()||!dirty())return;await action(async()=>{const edit=state.edit,sent=clone(edit.draft);await req('/packages/'+edit.id,json('PUT',{expected_revision:edit.revision,policy:sent}));const actual=await req('/packages/'+edit.id);if(!same(actual.policy,sent))throw Error('投放策略回读不一致，草稿已保留。');state.edit={...edit,revision:actual.revision,baseline:clone(actual.policy),draft:clone(actual.policy)};await load('',true);state.message='投放策略已保存并回读。安装状态等待逐台终端回执。';});}
  async function upload(){const file=state.file;if(!file||!canWrite())return;cancelled=false;await action(async()=>{if(file.size>state.max)throw Error('APK 超过文件大小上限。');const p=await req('/packages',json('POST',{name:file.name,size:file.size}));try{let offset=0;while(offset<file.size){if(!alive||cancelled)throw Error('上传已取消。');const body=await file.slice(offset,offset+state.chunk).arrayBuffer();const r=await req('/packages/'+p.id+'/content?offset='+offset,{method:'PUT',headers:{'Content-Type':'application/octet-stream'},body});offset=r.received;state.progress=`上传 ${Math.round(offset/file.size*100)}%`;const el=root.querySelector('[data-tv-pkg-progress]');if(el)el.textContent=state.progress;}await req('/packages/'+p.id+'/complete',json('POST',{}));state.file=null;state.progress='APK 校验完成，设置目标后可启用投放。';await load('',true);}catch(e){await req('/packages/'+p.id,{method:'DELETE'}).catch(()=>{});throw e;}});}
  function handleClick(event){const el=event.target.closest('[data-tv-pkg]');if(!el)return false;if(el.disabled)return true;const id=el.dataset.id,name=el.dataset.tvPkg;
    if(name==='reload')load('',true);
    if(name==='upload')upload();
    if(name==='source')action(async()=>{state.source=(await req('/releases/source?channel='+encodeURIComponent(state.channel))).latest;});
    if(name==='import'&&canWrite())action(async()=>{await req('/releases/import',json('POST',{channel:state.channel}));await load('',true);state.message='TV 发布包已导入并验证，默认暂停投放。';});
    if(name==='edit'){if(dirty()&&!window.confirm('放弃当前投放草稿？'))return true;const p=state.packages.find(v=>v.id===id);state.edit={id,kind:p.kind,name:p.metadata?.label||p.name,revision:p.revision,baseline:clone(p.policy),draft:clone(p.policy)};redraw();}
    if(name==='close-edit'){if(!dirty()||window.confirm('放弃投放草稿？'))state.edit=null;redraw();}
    if(name==='delete'&&canWrite()&&window.confirm('删除这份已暂停的 APK？'))action(async()=>{await req('/packages/'+id,{method:'DELETE'});if(state.edit?.id===id)state.edit=null;await load('',true);});
    return true;
  }
  function handleInput(event){const wasDirty=dirty();const el=event.target;if(el.matches('[data-tv-pkg-file]')){state.file=el.files?.[0]||null;redraw();return true;}
    if(el.matches('[data-tv-pkg-target]')){const t=state.edit.draft.target;t.ids=el.checked?[...new Set([...t.ids,el.value])]:t.ids.filter(v=>v!==el.value);}
    else{const key=el.dataset.tvPkgField;if(!key)return false;if(key==='channel'){state.channel=el.value;state.source=undefined;redraw();return true;}const p=state.edit?.draft;if(!p)return true;const v=el.type==='checkbox'?el.checked:el.type==='number'?Number(el.value):el.value;if(key==='target.mode')p.target={mode:v,ids:[]};else p[key]=v;}
    if(el.tagName==='SELECT'||el.type==='checkbox')redraw();else if(wasDirty!==dirty()){const bar=root.querySelector('[data-tv-pkg-savebar]');if(bar)bar.innerHTML=savebar();}return true;
  }
  return {load,render:markup,dirty,save,handleClick,handleInput,owns:tab=>tab==='apps'||tab==='upgrade',discard(){if(state.edit)state.edit.draft=clone(state.edit.baseline);state.error='';redraw();},destroy(){alive=false;cancelled=true;}};
}
