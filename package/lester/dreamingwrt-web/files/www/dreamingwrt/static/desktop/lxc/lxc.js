const API='/api/v1/container_service/lxc';
const VERSION='20261008-lxc-08';
const NAV=[['overview','概览','layout-dashboard'],['containers','容器','boxes'],['templates','模板','files'],['storage','存储','hard-drive'],['settings','设置','settings']];
const LABEL={not_installed:'未安装运行环境',degraded:'运行依赖不完整',ready:'运行环境已就绪',error:'读取失败',RUNNING:'运行中',STOPPED:'已停止',FROZEN:'已冻结',queued:'排队中',running:'执行中',success:'已完成',failed:'失败',cancelled:'已取消'};
const STAGE={clone:'复制容器 rootfs',snapshot:'创建完整快照',snapshot_restore:'恢复快照',snapshot_delete:'删除指定快照',restore_backup:'保留恢复前副本',download:'下载系统镜像',create:'创建容器',config_stop:'应用前停止',config_apply:'应用配置',config_start:'应用后启动',config_recover:'恢复配置',start:'正在启动',stop:'正在停止',restart:'正在重启',destroy:'正在删除',verified:'回读已确认',failed:'执行失败'};
const REASON={template_source_unavailable:'模板源当前无法访问，请重试',template_source_timeout:'读取模板源超时，请重试',template_architecture_mismatch:'与本机架构不匹配',lxc_create_pipeline_pending:'来源已核实，创建流程尚未就绪',template_catalog_no_supported_images:'源中没有支持的系统镜像',template_script_only:'已安装的模板脚本',container_operation_busy:'该容器已有任务，请先查询任务结果',container_identity_changed:'目标容器已被替换，请刷新后重试',container_must_be_stopped:'请先停止容器',container_not_running:'容器当前没有运行',force_confirmation_required:'强制停止需要单独确认',lxc_state_not_confirmed:'命令结束，但未确认目标状态，请回读容器',lxc_action_failed:'LXC 操作失败',lxc_action_timeout:'操作超时，请查看剩余对象状态',worker_interrupted:'任务进程中断，请先检查目标当前状态',lxc_command_missing:'缺少 LXC 命令',lxc_control_pipeline_pending:'受控操作链尚未就绪',lxc_runtime_commands_unavailable_or_not_validated:'运行依赖缺失或尚未验证',lxc_read_timeout:'运行时读取超时',lxc_read_failed:'LXC 命令读取失败',lxc_output_truncated:'输出超过读取上限',lxc_list_format_invalid:'容器列表格式无法识别',lxc_storage_unavailable:'目录不存在、未挂载或不可读取',lxc_path_read_failed:'无法确定 LXC 实际目录',lxc_multiple_paths_require_selection:'运行时配置了多个目录，需要明确选择',lxc_templates_not_installed:'尚未安装模板脚本',lxc_templates_unreadable:'无法读取模板目录',template_source_not_verified:'仅发现模板脚本，发行版与来源尚未验证',source_verification_pending:'模板来源待验证',container_not_found:'容器不存在',lxc_log_source_unavailable:'配置未提供可读取的运行日志来源',lxc_log_not_found_or_not_regular:'运行日志不存在或不是普通文件',lxc_config_authority_pending:'配置管理尚未接通，保留现有原始配置'};
Object.assign(REASON,{lxc_config_revision_conflict:'配置版本已变化，请保留草稿并重新读取',lxc_config_external_conflict:'配置文件被外部修改，请保留草稿并检查差异',lxc_config_takeover_required:'需要明确确认接管配置',lxc_config_state_conflict:'配置当前状态不允许此操作，请刷新',restart_confirmation_required:'应用需要单独确认重启影响',lxc_config_recovery_required:'上次应用未完成，请先恢复',lxc_config_storage_failed:'配置持久化失败，请保留草稿',lxc_config_start_failed:'新配置启动失败，请检查恢复结果',lxc_stop_not_confirmed:'未确认容器已正常停止',lxc_config_write_failed:'写入配置失败，请检查恢复结果'});
Object.assign(REASON,{lxc_create_dependencies_missing:'缺少创建所需命令或 lxc-local 模板',lxc_bridge_unavailable:'所选网桥已不可用',lxc_userns_mapping_unavailable:'未配置可用的非特权用户映射',lxc_storage_insufficient:'存储可用空间不足，未执行操作',lxc_name_exists:'该名称已存在',lxc_storage_changed:'存储目录身份已改变，请重新选择',template_changed_or_unavailable:'模板构建版本已变化，请刷新模板',template_download_failed:'系统镜像下载失败',lxc_create_failed:'创建失败，请查看任务输出和剩余路径',lxc_create_start_failed:'容器已创建，但启动失败'});
Object.assign(REASON,{lxc_maintenance_requires_managed_container:'此容器没有可验证的创建记录，克隆与快照不可用',lxc_storage_backend_unsupported:'当前仅支持受管目录存储的完整复制',lxc_snapshot_changed:'快照已被替换，请刷新后重新选择',lxc_snapshot_not_found:'快照已不存在',lxc_restore_backup_failed:'未能保留完整回退副本，恢复未执行',lxc_snapshot_action_failed:'快照操作失败，请检查任务中的回退副本',lxc_clone_failed:'克隆失败，请检查剩余复制目录',lxc_network_mounts_require_managed_layout:'当前外部配置的网络与挂载布局不可编辑',invalid_bridge:'网桥名称无效',invalid_mount:'挂载目录或只读选项无效',duplicate_mount_target:'容器内挂载目录重复'});
const esc=v=>String(v??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const reason=v=>REASON[v]||v||'能力信息尚未提供';
const glyph=v=>`<i data-lucide="${esc(v)}" aria-hidden="true"></i>`;
const bytes=v=>v==null?'未知':new Intl.NumberFormat('zh-CN',{maximumFractionDigits:1}).format(v/(v>=1073741824?1073741824:v>=1048576?1048576:1024))+(v>=1073741824?' GiB':v>=1048576?' MiB':' KiB');
const cell=v=>`<td>${esc(v??'未知')}</td>`;
export function normalize(data={}) {
  const l=data.lxc||data,config=l.config||l.uci_config||{};
  return {...l,config,containers:Array.isArray(l.containers)?l.containers:null,missing_commands:l.missing_commands||l.missing||Object.entries(l.commands||{}).filter(([,v])=>!v).map(([k])=>k),environment_state:l.environment_state||(l.available?'degraded':Object.values(l.commands||{}).some(Boolean)?'degraded':'not_installed')};
}
export function mount(context={}) {
  const root=context.root||document.getElementById('lxcApp'),host=context.host||'traditional',kit=window.DWRT_UI_KIT||context.ui;
  if(!root)return {unmount(){}};
  const originalClass=root.className,owner='lxc-'+Math.random().toString(36).slice(2);
  const s={alive:true,view:'overview',data:null,error:'',loading:false,sheet:null,query:'',filter:'',templates:null,jobs:null,confirm:null,mutating:false,jobId:null};
  root.classList.add('lxc-route');
  for(const [key,url] of [['lxc','/static/desktop/lxc/lxc.css?v='+VERSION],['rail','/static/desktop/dwrt-rail.css?v=20261008-desktop-material-01']]){
    if(!document.querySelector(`link[data-lxc-style="${key}"]`)){const link=document.createElement('link');link.rel='stylesheet';link.href=url;link.dataset.lxcStyle=key;document.head.append(link);}
  }
  const caps=()=>s.data?.capabilities||{};
  const role=()=>window.DWRT_SESSION?.tokens?.().role||'';
  const permitted=risk=>risk==='low'?true:risk==='high'?role()==='owner':['owner','admin'].includes(role());
  function button(action,label,cap='',risk='medium',extra='') {
    const why=cap&&!permitted(risk)?'当前账号没有此操作权限':cap&&!caps()[cap]?reason(s.data?.capability_reasons?.[cap]):'';
    return `<button data-dwrt-id="${esc(action+'-'+extra)}" type="button" class="dwrt-kit-button" data-dwrt-component="button" data-lxc-action="${esc(action)}" ${why?'disabled':''} title="${esc(why)}" ${extra}>${esc(label)}</button>`;
  }
  async function request(path='',method='GET',body) {
    const response=await (window.DWRT_REQUEST?.fetch||window.fetch.bind(window))(API+path,{method,credentials:'same-origin',cache:'no-store',headers:{Accept:'application/json',...(body?{'Content-Type':'application/json'}:{})},...(body?{body:JSON.stringify(body)}:{})});
    let payload;try{payload=await response.json();}catch(_){throw new Error(`HTTP ${response.status}：响应不是 JSON`);}
    const data=payload.data??payload;
    if(!response.ok||payload.ok===false||(payload.code!=null&&![0,200,2000].includes(Number(payload.code)))||data.ok===false){
      const error=new Error(response.status===401?'登录已过期':response.status===403?'当前账号没有读取权限':reason(data.error||data.reason||payload.message));error.data=data;throw error;
    }
    return data;
  }
  const paint=scope=>{kit?.mountAll?.(scope||root);window.lucide?.createIcons?.();};
  function nav(){return NAV.map(([id,label,icon])=>`<button type="button" class="${host==='desktop'?'dwrt-rail-item':'dwrt-kit-tab'} ${s.view===id?'is-active':''}" data-lxc-view="${id}" aria-label="${label}" aria-current="${s.view===id?'page':'false'}" title="${label}"><span class="dwrt-rail-item-icon">${glyph(icon)}</span><span class="dwrt-rail-item-text">${label}</span></button>`).join('');}
  function table(labels,rows,row,empty){return `<section class="lxc-table-wrap dwrt-kit-table-wrap dwrt-kit-glass-surface"><div class="dwrt-kit-table-scroll"><table class="dwrt-kit-table lxc-table"><thead><tr>${labels.map(v=>`<th>${esc(v)}</th>`).join('')}</tr></thead><tbody>${rows?.length?rows.map(row).join(''):`<tr><td colspan="${labels.length}" class="lxc-empty">${esc(empty)}</td></tr>`}</tbody></table></div></section>`;}
  const info=entries=>`<dl class="lxc-info">${entries.map(([key,value])=>`<dt>${esc(key)}</dt><dd>${esc(value??'未知')}</dd>`).join('')}</dl>`;
  function render(){
    root.innerHTML=`<div class="lxc-workbench" data-host="${host}">${host==='desktop'?`<aside class="dwrt-rail"><div class="dwrt-rail-brand"><img src="/static/images/logo-wide.png" alt="DreamingOS"></div><nav class="dwrt-rail-list" aria-label="LXC 功能">${nav()}</nav></aside>`:`<nav class="lxc-tabs dwrt-kit-tabs dwrt-kit-page-tabs" aria-label="LXC 功能">${nav()}</nav>`}<main class="lxc-main"><header class="lxc-toolbar"><h1 data-view-title>概览</h1>${button('tasks','任务')}</header><p class="lxc-notice" role="status"></p><div class="lxc-body" data-body></div></main></div>`;renderContent();
  }
  function renderContent(){
    const body=root.querySelector('[data-body]');
    const oldScroll=body.scrollTop,tableScroll=body.querySelector('.dwrt-kit-table-scroll'),left=tableScroll?.scrollLeft||0,top=tableScroll?.scrollTop||0;
    root.querySelector('[data-view-title]').textContent=NAV.find(v=>v[0]===s.view)?.[1]||'任务';
    root.querySelector('.lxc-notice').textContent=s.error;
    root.querySelectorAll('[data-lxc-view]').forEach(n=>{n.classList.toggle('is-active',n.dataset.lxcView===s.view);n.setAttribute('aria-current',n.dataset.lxcView===s.view?'page':'false');});
    if(!s.data){body.innerHTML=`<div class="lxc-empty">${esc(s.error?'读取失败，保留当前页面并自动重试。':'正在读取 LXC 运行环境…')}</div>`;return;}
    const d=s.data,rows=d.containers;
    if(s.view==='overview'){
      body.innerHTML=`<div class="lxc-overview">${[['运行环境',LABEL[d.environment_state]||d.environment_state],['运行中',rows?rows.filter(v=>v.state==='RUNNING').length:'未知'],['已停止',rows?rows.filter(v=>v.state==='STOPPED').length:'未知']].map(([k,v])=>`<section class="lxc-metric dwrt-kit-glass-surface"><span>${k}</span><strong>${esc(v)}</strong></section>`).join('')}</div>${info([['版本',d.version||'尚未读取'],['架构',d.architecture],['容器目录',d.config.lxcpath],['可用空间',bytes(d.storage?.available_bytes)]])}${d.missing_commands.length?`<p>缺少运行依赖：${esc(d.missing_commands.join('、'))}</p>`:''}<p class="lxc-muted">${caps().actions?'按每个容器的状态执行操作。':reason(d.capability_reasons?.actions)}</p>`;
    }else if(s.view==='containers'){
      const filtered=(rows||[]).filter(v=>(!s.filter||v.state===s.filter)&&v.name?.toLowerCase().includes(s.query.toLowerCase()));
      body.innerHTML=`<div class="dwrt-kit-table-toolbar lxc-actions"><span class="dwrt-kit-field lxc-search"><input class="dwrt-kit-input" data-query aria-label="搜索容器" placeholder="搜索容器" value="${esc(s.query)}"></span><select class="dwrt-kit-select" data-filter aria-label="容器状态"><option value="">全部状态</option>${['RUNNING','STOPPED','FROZEN'].map(v=>`<option value="${v}" ${s.filter===v?'selected':''}>${LABEL[v]}</option>`).join('')}</select>${button('create','创建容器','create','high')}</div>`+table(['名称','状态','自启','实际地址','操作'],filtered,v=>`<tr>${cell(v.name)}${cell(LABEL[v.state]||v.state)}${cell(v.autostart==null?'未知':v.autostart?'开启':'关闭')}${cell([v.ipv4,v.ipv6].filter(Boolean).join(' · ')||'尚无地址')}<td class="lxc-actions">${button('detail','详情','','medium',`data-name="${esc(v.name)}"`)}${button(v.state==='RUNNING'?'stop':'start',v.state==='RUNNING'?'停止':'启动',v.state==='RUNNING'?'stop':'start','high',`data-name="${esc(v.name)}" data-identity="${esc(v.identity)}"${!['RUNNING','STOPPED'].includes(v.state)?' disabled':''}`)}</td></tr>`,rows?'没有匹配的容器':'无法取得容器列表，检查运行依赖与读取状态。');
    }else if(s.view==='templates'){
      const t=s.templates;
      body.innerHTML=`<div class="lxc-actions">${button('refresh-templates','刷新模板')}</div>`+(t?table(['模板','类型','状态'],t.catalog?.length?t.catalog:(t.scripts||t.templates?.map(id=>({id}))||[]),v=>`<tr>${cell(v.id||v.name)}${cell(v.distribution?`${v.distribution} ${v.release} / ${v.architecture}`:'模板脚本')}${cell(v.creatable?'可创建':reason(v.reason||'template_source_not_verified'))}</tr>`,'尚无通过来源及架构校验的模板'): '<div class="lxc-empty">正在读取模板…</div>');
    }else if(s.view==='storage'){
      body.innerHTML=info([['运行时目录',d.storage?.path||d.config.lxcpath],['可读取',d.storage?.available?'是':reason(d.storage?.reason)],['总容量',bytes(d.storage?.total_bytes)],['可用空间',bytes(d.storage?.available_bytes)],['容器引用',rows?rows.length:'未知']])+'<p class="lxc-muted">默认新建位置与已有容器数据分开管理。改变默认位置不会迁移已有数据。</p>';
    }else if(s.view==='settings'){
      body.innerHTML=`<div class="lxc-actions">${button('edit-settings','修改新建默认值','settings_write','high')}</div>`+info([['当前目录',d.config.lxcpath],['路径来源',d.config.path_source||'现有配置'],['cgroup',d.environment?.cgroup_version],['可用控制器',d.environment?.cgroup_controllers]])+table(['命令','状态'],Object.entries(d.commands||{}),([k,v])=>`<tr>${cell(k)}${cell(v?'已安装':'缺失')}</tr>`,'未取得依赖信息')+`<p class="lxc-muted">默认位置仅影响新建容器，不迁移已有数据。</p>`;
    }else if(s.view==='tasks'){
      body.innerHTML=caps().jobs?table(['目标','状态','阶段','操作'],s.jobs||[],v=>`<tr>${cell(v.result?.name||v.target)}${cell(LABEL[v.state]||v.state)}${cell(STAGE[v.result?.stage]||(v.error?reason(v.error):'等待执行'))}<td class="lxc-actions">${button('job','详情','','high',`data-job="${esc(v.job_id)}"`)}${['queued','running'].includes(v.state)?button('cancel-job','取消','jobs','high',`data-job="${esc(v.job_id)}"`):''}</td></tr>`,'没有任务'):`<div class="lxc-empty">${esc(reason(d.capability_reasons?.jobs||'lxc_control_pipeline_pending'))}</div>`;
    }
    body.scrollTop=oldScroll;const next=body.querySelector('.dwrt-kit-table-scroll');if(next){next.scrollLeft=left;next.scrollTop=top;}paint();
  }
  function visible(){try{return !document.hidden&&root.getClientRects().length&&(!window.frameElement||window.frameElement.getClientRects().length);}catch(_){return !document.hidden;}}
  function interacting(node){
    const active=document.activeElement,selection=window.getSelection();
    return (node?.contains(active)&&active.matches('input,textarea,select,[contenteditable="true"]'))||
      (selection&&!selection.isCollapsed&&node?.contains(selection.anchorNode));
  }
  async function refresh(){
    if(!s.alive||s.loading)return;s.loading=true;
    try{
      const data=normalize(await request());if(!s.alive)return;s.data=data;s.error='';
      if(s.view==='templates'&&!s.templates)s.templates=await request('/templates');
      if(s.view==='tasks'&&caps().jobs)s.jobs=(await request('/jobs?limit=30')).items||[];
    }catch(error){if(!s.alive)return;if(!s.data&&error.data?.commands)s.data=normalize(error.data);s.error=error.message+(s.data?'；保留上次成功读取的数据。':'');}
    finally{s.loading=false;if(s.alive&&!s.sheet&&!interacting(root.querySelector('[data-body]')))renderContent();else if(s.alive)root.querySelector('.lxc-notice').textContent=s.error;}
  }
  function confirm(title,description){
    if(s.confirm)return Promise.resolve(false);
    const node=document.createElement('div');node.innerHTML=kit.confirmationMarkup({id:owner+'-confirm',tone:'warning',title,description,confirmLabel:'确认'});document.body.append(node);
    const previous=document.activeElement;
    return new Promise(resolve=>{const finish=value=>{node.remove();s.confirm=null;previous?.focus?.({preventScroll:true});resolve(value);};s.confirm={finish};
      node.addEventListener('click',event=>{if(event.target.closest('[data-dwrt-confirm-accept]'))finish(true);else if(event.target.closest('[data-dwrt-confirm-cancel]'))finish(false);});node.querySelector('[data-dwrt-confirm-cancel]').focus();});
  }
  async function mutate(path,method,body={}){
    if(s.mutating)return;s.mutating=true;
    try{const result=await request(path,method,{...body,confirm:true});await closeSheet(true);s.view='tasks';await refresh();s.error=result.job_id?'已提交任务；请查看任务终态与容器回读。':'操作已受理。';renderContent();return true;}
    catch(error){s.error=error.message+'；请先查询任务与容器状态，再决定是否重试。';root.querySelector('.lxc-notice').textContent=s.error;return false;}
    finally{s.mutating=false;}
  }
  async function jobDetail(id,open=false){
    if(open){await sheet('任务详情','<div data-job-detail></div>');s.jobId=id;}
    const job=await request('/jobs/'+encodeURIComponent(id));if(!s.alive||s.jobId!==id)return;
    const node=s.sheet?.element.querySelector('[data-job-detail]');if(!node||interacting(node))return;
    node.innerHTML=info([['目标',job.result?.name||job.target],['状态',LABEL[job.state]||job.state],['阶段',STAGE[job.result?.stage]||'等待执行'],['错误',job.error?reason(job.error):'无'],['对象回读',job.result?.readback_required?'需要重新读取':job.result?.state||'尚未取得'],['遗留路径',job.result?.remaining_path||job.result?.remaining_copy_path||'无'],['下载临时目录',job.result?.staging_present?job.result.staging_path:'无'],['回退副本',job.result?.rollback_container||'无'],['回退副本可用',job.result?.rollback_ready?'是':'尚未确认'],['遗留对象',job.result?.remaining_object===true?'目标仍存在':job.result?.remaining_object===false?'目标已不存在':'尚未确认']])+`<pre>${esc(job.output||'暂无输出')}</pre>${['queued','running'].includes(job.state)?button('cancel-job','取消任务','jobs','high',`data-job="${esc(id)}"`):''}`;
    paint(node);
  }
  async function closeSheet(force=false){if(!s.sheet)return true;const x=s.sheet;if(!force&&x.editor?.isDirty()&&!await confirm('放弃尚未保存的修改？','当前配置草稿将被丢弃。'))return false;x.editor?.close();x.terminal?.close();s.sheet=null;s.jobId=null;x.host.append(x.element,x.overlay);kit?.unmount?.(x.host);x.host.remove();return true;}
  async function sheet(title,content,footer='',form=false){
    if(!await closeSheet()||!s.alive)return false;
    const node=document.createElement('div');node.dataset.lxcOwner=owner;root.append(node);
    node.innerHTML=`<button class="dwrt-kit-sheet-overlay is-open" data-lxc-owner="${owner}" data-lxc-action="close" aria-label="关闭"></button><aside class="dwrt-kit-sheet lxc-sheet is-open" data-lxc-owner="${owner}" data-dwrt-component="sheet" data-dwrt-sheet-size="${form?'form':'wide'}" aria-label="${esc(title)}"><header class="dwrt-kit-sheet-header"><strong>${esc(title)}</strong>${button('close','关闭')}</header><div class="dwrt-kit-sheet-body">${content}</div><footer class="dwrt-kit-sheet-footer">${footer}</footer></aside>`;
    s.sheet={host:node,element:node.querySelector('aside'),overlay:node.querySelector('.dwrt-kit-sheet-overlay')};paint(node);return true;
  }
  async function handle(event){
    const target=event.target.closest('[data-lxc-action],[data-lxc-view]');
    if(!target||target.disabled||(!root.contains(target)&&target.closest('[data-lxc-owner]')?.dataset.lxcOwner!==owner))return;
    event.preventDefault();
    if(target.dataset.lxcView){s.view=target.dataset.lxcView;renderContent();refresh();return;}
    const action=target.dataset.lxcAction,name=target.dataset.name;
    if(action==='close'){closeSheet();return;}
    if(action==='tasks'){s.view='tasks';renderContent();refresh();return;}
    if(action==='refresh-templates'){s.templates=null;renderContent();refresh();return;}
    try{
      if(action==='create'){
        if(!permitted('high')||!caps().create)return;
        const previous=s.sheet,settings=await request('/config'),templates=await request('/templates');
        const module=await import('./lxc-create.js?v='+VERSION);
        if(!s.alive||s.sheet!==previous)return;
        const markup=module.createMarkup(settings,templates,kit);
        if(!await sheet('创建 LXC 容器',markup.body,markup.footer,true))return;
        const current=s.sheet;current.editor=module.mountCreate({element:current.element,settings,templates,request,confirm,submit:mutate,isAlive:()=>s.alive&&s.sheet===current});return;
      }
      if(action==='edit-settings'){
        if(!permitted('high'))return;
        const previous=s.sheet,document=await request('/config'),templates=await request('/templates').catch(()=>({catalog:[]}));
        const module=await import('./lxc-settings.js?v='+VERSION);
        if(!s.alive||s.sheet!==previous)return;
        const markup=module.settingsMarkup(document,templates,kit);
        if(!await sheet('新建容器默认值',markup.body,markup.footer,true))return;
        const current=s.sheet;
        current.editor=module.mountSettings({element:current.element,document,request,isAlive:()=>s.alive&&s.sheet===current,saved:async()=>{await closeSheet();await refresh();s.error='新建默认值已保存，已有容器未迁移。';renderContent();}});return;
      }
      if(['start','stop','restart','destroy','force-stop'].includes(action)){
        const row=s.data?.containers?.find(v=>v.name===name);if(!row?.identity)throw new Error('目标身份尚未确认，请刷新后重试。');
        const op=action==='force-stop'?'stop':action;
        const wording={start:['启动容器？','启动所选容器。'],stop:['停止容器？','正常停止；超时不会自动强制结束。'],restart:['重启容器？','先正常停止再启动，容器内服务会短暂中断。'],destroy:['删除容器与 rootfs？','永久删除所选已停止容器的配置和 rootfs；外部绑定目录不随删除清理。'],'force-stop':['强制停止容器？','立即结束容器进程，未写入磁盘的数据可能丢失。']}[action];
        if(await confirm(wording[0],name+' · '+wording[1]))await mutate('/container/'+encodeURIComponent(name)+(op==='destroy'?'':'/'+op),op==='destroy'?'DELETE':'POST',{identity:row.identity,...(action==='force-stop'?{force:true,force_confirm:true}:{})});return;
      }
      if(action==='job'){await jobDetail(target.dataset.job,true);return;}
      if(action==='cancel-job'){if(await confirm('取消任务？','已执行的步骤不会自动撤销；取消后需检查目标当前状态。'))await mutate('/jobs/'+encodeURIComponent(target.dataset.job),'DELETE');return;}
      if(action==='detail'){
        const row=s.data?.containers?.find(v=>v.name===name)||{};
        await sheet(name,info([['名称',name],['状态',LABEL[row.state]||row.state],['地址',[row.ipv4,row.ipv6].filter(Boolean).join(' · ')||'尚无地址']])+`<div class="lxc-actions">${['config','logs','stats','processes'].map(v=>button(v,{config:'配置',logs:'运行日志',stats:'资源',processes:'进程'}[v],'','medium',`data-name="${esc(name)}"`)).join('')}${button('maintenance','克隆与快照','snapshot_list','low',`data-name="${esc(name)}"`)}${button('terminal','终端','terminal','medium',`data-name="${esc(name)}"${row.state!=='RUNNING'?' disabled':''}`)}${(row.state==='RUNNING'?['restart','force-stop']:row.state==='STOPPED'?['destroy']:[]).map(op=>button(op,{restart:'重启','force-stop':'强制停止',destroy:'删除'}[op],op==='force-stop'?'stop':op,'high',`data-name="${esc(name)}"`)).join('')}</div><div data-detail></div>`);return;
      }
      if(action==='maintenance'){
        const previous=s.sheet,data=await request('/container/'+encodeURIComponent(name)+'/snapshots');
        const module=await import('./lxc-maintenance.js?v='+VERSION);
        if(!s.alive||s.sheet!==previous)return;
        const canWrite=permitted('high')&&s.data?.containers?.find(row=>row.name===name)?.state==='STOPPED';
        if(!await sheet(name+' · 克隆与快照',module.maintenanceMarkup(data,canWrite,caps()),'',true))return;
        const current=s.sheet;current.editor=module.mountMaintenance({element:current.element,document:data,name,request,confirm,submit:mutate,isAlive:()=>s.alive&&s.sheet===current,canWrite});return;
      }
      if(action==='terminal'){
        const row=s.data?.containers?.find(v=>v.name===name),previous=s.sheet;
        if(!row?.identity||row.state!=='RUNNING')throw new Error('请先刷新并启动目标容器。');
        const capability=await request('/terminal/capabilities');
        const module=await import('./lxc-terminal.js?v='+VERSION);
        if(!s.alive||s.sheet!==previous)return;
        if(!capability.terminal||!capability.connect)throw new Error(module.terminalReason(capability.reason));
        await sheet(name+' · 终端',`<p class="lxc-muted">关闭此面板会结束终端会话。</p><div class="lxc-actions"><label class="dwrt-kit-field">Shell<select class="dwrt-kit-select" data-terminal-shell>${(capability.shells||[]).map(shell=>`<option>${esc(shell)}</option>`).join('')}</select></label><button class="dwrt-kit-button" data-dwrt-component="button" data-terminal-connect>连接</button><button class="dwrt-kit-button" data-dwrt-component="button" data-terminal-disconnect disabled>断开</button></div><p data-terminal-state role="status"></p><div class="lxc-terminal-pane" data-container-terminal aria-label="容器交互终端"></div>`);
        s.sheet.element.classList.add('lxc-terminal-sheet');
        s.sheet.terminal=module.mountTerminal({element:s.sheet.element,containerId:name,identity:row.identity,workspace:owner,request:(path,method,body)=>request(path.slice(API.length),method,body)});return;
      }
      if(action==='config'){
        const previous=s.sheet,data=await request('/container/'+encodeURIComponent(name)+'/config');
        const module=await import('./lxc-config.js?v='+VERSION);
        if(!s.alive||s.sheet!==previous)return;
        const markup=module.configMarkup(data,kit,permitted('high'));
        if(!await sheet(name+' · 配置',markup.body,markup.footer,true))return;
        const current=s.sheet;
        current.editor=module.mountConfig({element:current.element,document:data,name,request,confirm,submit:mutate,isAlive:()=>s.alive&&s.sheet===current,canWrite:permitted('high')});return;
      }
      if(['logs','stats','processes'].includes(action)){
        const current=s.sheet;
        const data=await request('/container/'+encodeURIComponent(name)+'/'+action);if(!s.sheet)return;
        if(s.sheet!==current)return;
        const target=s.sheet.element.querySelector('[data-detail]');
        target.innerHTML=action==='stats'?info([['状态',LABEL[data.state]||data.state],['CPU 累计秒',data.cpu_seconds],['内存使用',bytes(data.memory_usage_bytes)],['内存上限',bytes(data.memory_limit_bytes)],['网络累计接收',bytes(data.network_rx_bytes)],['网络累计发送',bytes(data.network_tx_bytes)]]):`<p class="lxc-muted">${esc(action==='logs'?data.log_path:action==='config'?data.config_path:'容器内进程')}</p><pre>${esc(data[action]||'暂无内容')}</pre>`;
      }
    }catch(error){if(s.sheet){const node=s.sheet.element.querySelector('[data-detail]');if(node)node.textContent=error.message;}else{s.error=error.message;renderContent();}}
  }
  function input(event){if(!root.contains(event.target))return;if(event.target.matches('[data-query]')){s.query=event.target.value;const start=event.target.selectionStart;renderContent();const node=root.querySelector('[data-query]');node.focus({preventScroll:true});node.setSelectionRange(start,start);}if(event.target.matches('[data-filter]')){s.filter=event.target.value;renderContent();}}
  const escape=event=>{if(event.key==='Escape'&&s.confirm){event.preventDefault();s.confirm.finish(false);return;}if(event.key==='Escape'&&s.sheet){event.preventDefault();if(event.target.closest('[data-container-terminal]'))s.sheet.terminal?.escape();else closeSheet();}};
  document.addEventListener('click',handle,true);root.addEventListener('input',input);root.addEventListener('change',input);document.addEventListener('keydown',escape);
  render();refresh();const timer=setInterval(()=>{if(visible()&&!s.confirm){if(s.jobId)jobDetail(s.jobId).catch(error=>{s.error=error.message;root.querySelector('.lxc-notice').textContent=s.error;});else if(!s.sheet)refresh();}},3000);
  return {refresh,unmount(){s.alive=false;s.confirm?.finish(false);clearInterval(timer);closeSheet(true);document.removeEventListener('click',handle,true);root.removeEventListener('input',input);root.removeEventListener('change',input);document.removeEventListener('keydown',escape);root.replaceChildren();root.className=originalClass;}};
}
