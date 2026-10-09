const API = '/api/v1/container_service/docker';
const VERSION = '20261005-docker-05';
const NAV = [['overview','概览','layout-dashboard'],['containers','容器','box'],['compose','Compose','layers'],['images','本地镜像','hard-drive'],['registry','镜像仓库','search'],['networks','网络','network'],['volumes','卷','database'],['settings','设置','settings']];
const LABEL = {not_installed:'未安装',stopped:'已停止',ready:'正常',unreachable:'无法连接引擎',error:'部分读取失败',running:'运行中',paused:'已暂停',created:'已创建',exited:'已停止',dead:'异常',queued:'排队中',success:'成功',failed:'失败',cancelled:'已取消'};
const esc = value => String(value ?? '').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const glyph = name => `<i data-lucide="${esc(name)}" aria-hidden="true"></i>`;
const bytes = value => { if(value==null)return '未上报';const n=Number(value),unit=n>=1073741824?'GiB':n>=1048576?'MiB':n>=1024?'KiB':'B',scale={GiB:1073741824,MiB:1048576,KiB:1024,B:1}[unit];return new Intl.NumberFormat('zh-CN',{maximumFractionDigits:1}).format(n/scale)+' '+unit; };
const describe = error => {
  const reasons={container_primary_network_uses_immutable_id:'容器主网络绑定了不可变网络 ID，直接重建后无法重新连接；请先通过容器重建改用网络名称',network_recreate_unsupported:'此网络的驱动、归属或 IPAM 结构暂不支持完整重建',network_disconnect_confirmation_required:'需明确确认断开网络端点',network_recreate_keeps_name_and_driver:'重建保留网络名称和驱动',network_recreate_requires_subnet:'重建必须指定 IPv4 子网',static_endpoint_outside_subnet:'容器静态地址不属于新子网，请先调整方案',network_recovery_identity_conflict:'同名网络已由其他操作替换，恢复已停止',parent_network_requires_subnet_gateway_and_range:'macvlan/ipvlan 必须填写子网、网关和预留地址池',existing_ethernet_parent_required:'请选择当前存在的以太网父接口',address_pool_contains_parent_address:'地址池包含父接口的主机地址，请缩小或调整范围',confirm_reserved_pool_outside_dhcp:'请确认地址池已预留，并与局域网 DHCP 分配范围分开',network_driver_unavailable:'当前引擎不支持此网络驱动',network_options_unavailable:'无法读取网络驱动或父接口',subnet_overlaps_host_route_or_docker_network:'子网与现有网络冲突',host_route_read_failed:'无法读取主机路由，请稍后重试',network_name_already_exists:'网络名称已存在',canonical_ipv4_subnet_required_prefix_1_to_30:'请输入正确的 IPv4 网络地址和前缀（1–30）',gateway_must_be_usable_address_in_subnet:'网关必须是子网内可用的主机地址',canonical_range_must_be_inside_subnet:'地址池必须位于子网内，并使用网络地址/前缀格式'};
  const conflicts=(error.conflicts||[]).map(x=>`${x.source==='host_route'?'主机路由':'Docker 网络'} ${x.name} · ${x.subnet}`).join('；');
  const settingsReasons={docker_migration_driver_unsupported:'当前存储驱动不支持文件迁移；支持 overlayfs、overlay2 和 vfs',docker_migration_bind_inside_data_root:'容器绑定了 Docker 数据目录内的固定路径，请先调整该挂载',rsync_metadata_support_unavailable:'复制工具缺少 ACL 或扩展属性支持',docker_migration_target_not_persistent:'目标必须位于已配置开机挂载的可写磁盘',docker_migration_target_not_empty:'请选择空目录；可先在文件管理中创建目录',docker_migration_paths_overlap:'源目录与目标目录不能相同或互相包含',docker_containerd_root_unresolved_or_external:'无法确认 Docker 独占的 containerd 数据位置',docker_migration_insufficient_space:'目标可用空间不足',docker_migration_inventory_unsupported:'当前有自动删除、暂停或重启中的容器，或外部卷，暂不能迁移',docker_migration_live_restore_or_swarm:'请先关闭 Live Restore 或退出 Swarm，再安排离线迁移',docker_migration_jobs_busy:'请等待其他 Docker 任务结束',docker_migration_recovery_required:'上次迁移尚未结束，请先恢复原数据目录',docker_migration_copy_failed:'数据复制失败，请查看恢复结果',docker_migration_verify_failed:'复制数据未通过完整校验',docker_migration_readback_failed:'新位置启动或对象回读失败',docker_migration_stop_confirmation_required:'需明确确认停止 Docker 服务',revision_conflict:'配置已被其他操作更新，请重新打开编辑器后核对',invalid_docker_settings:'请填写有效的镜像源地址与开机启动选项',docker_settings_external_change:'设备配置已被外部修改，请先核对，工作台没有覆盖这些修改',docker_settings_recovery_or_apply_pending:'引擎配置正在应用或等待恢复',docker_settings_recovery_required:'上次应用尚未结束，请先恢复',docker_settings_busy:'引擎配置正在处理，请稍后重试',docker_restart_confirmation_required:'修改镜像源需要确认重启 Docker 引擎',docker_settings_apply_failed:'引擎配置应用失败，请查看任务中的恢复结果',docker_alternate_config_active:'引擎正在使用独立配置文件，暂不能在此编辑',docker_uci_unavailable_or_uncommitted:'设备配置不可读取或存在尚未提交的修改',docker_settings_storage_unavailable:'配置存储尚不可用'};
  return [error.field,error.message || reasons[error.reason] || reasons[error.error] || settingsReasons[error.error] || settingsReasons[error.reason] || error.reason || error.error || '请求失败',conflicts].filter(Boolean).join('：');
};

export function mount(context={}) {
  const root=context.root, host=context.host || 'traditional', kit=window.DWRT_UI_KIT || context.ui;
  if(!root) return {unmount(){}};
  const id=`docker-${Math.random().toString(36).slice(2)}`;
  const s={alive:true,data:null,error:'',view:'overview',query:'',filter:'',busy:false,jobs:[],sheet:null,confirm:null,refreshing:false,signature:'',selected:new Set(),projects:[],projectError:'',registry:null,registryKeyword:'',registryPage:1,monitor:[],monitorKey:'',monitorError:'',statsLoading:false,previousSample:null};
  const originalClass=root.className;
  s.engineSettings=null;s.engineError='';
  root.classList.add('docker-route');
  for(const [key,url] of [['docker','/static/desktop/docker/docker.css?v='+VERSION],['rail','/static/desktop/dwrt-rail.css?v=20260927-rail-spec-01']]) {
    if(!document.querySelector(`link[data-docker-style="${key}"]`)) {
      const link=document.createElement('link');link.rel='stylesheet';link.href=url;link.dataset.dockerStyle=key;document.head.append(link);
    }
  }
  const caps=()=>s.data?.capabilities || {};
  const role=()=>window.DWRT_SESSION?.tokens?.().role || '';
  const authorized=(risk='medium')=>risk==='high' ? role()==='owner' : ['owner','admin'].includes(role());
  const enabled=(cap,risk)=>Boolean(caps()[cap] && authorized(risk));
  function button(action,label,cap='',risk='medium',extra='') {
    const disabled=s.busy || (cap && !enabled(cap,risk));
    const reason=cap&&!authorized(risk)?'当前账号没有此操作权限':cap&&!caps()[cap]?'当前引擎不支持此操作':'';
    return `<button type="button" class="dwrt-kit-button" data-dwrt-component="button" data-dwrt-key="${esc(action+':'+extra)}" data-docker-action="${action}" ${disabled?'disabled':''} title="${esc(reason)}" ${extra}>${esc(label)}</button>`;
  }
  async function request(path='',method='GET',body) {
    const response=await (window.DWRT_REQUEST?.fetch || window.fetch.bind(window))(path.startsWith('/api/')?path:API+path,{method,credentials:'same-origin',cache:'no-store',headers:{Accept:'application/json',...(body?{'Content-Type':'application/json'}:{})},...(body?{body:JSON.stringify(body)}:{})});
    let payload;try{payload=await response.json();}catch(_){throw new Error(`HTTP ${response.status}：返回内容不是 JSON`);}
    const data=payload.data ?? payload;
    if(!response.ok || payload.ok===false || (payload.code!=null && ![0,200,2000].includes(Number(payload.code))) || data?.ok===false) {
      const error=new Error(response.status===401?'登录已过期':response.status===403?'当前账号没有此操作权限':describe(data));error.status=response.status;throw error;
    }
    return data;
  }
  const paint=()=>{kit?.mountAll?.(root);window.lucide?.createIcons?.();};
  function nav() {
    return NAV.map(([key,title,icon])=>host==='desktop'?`<button class="dwrt-rail-item ${s.view===key?'is-active':''}" data-docker-view="${key}" title="${title}" aria-label="${title}" aria-current="${s.view===key?'page':'false'}"><span class="dwrt-rail-item-icon">${glyph(icon)}</span><span class="dwrt-rail-item-text">${title}</span></button>`:`<button data-dwrt-component="button" class="dwrt-kit-button ${s.view===key?'is-active':''}" data-docker-view="${key}" aria-pressed="${s.view===key}">${title}</button>`).join('');
  }
  function render() {
    if(!s.alive)return;
    root.innerHTML=`<div class="docker-workbench" data-host="${host}">${host==='desktop'?`<aside class="dwrt-rail"><div class="dwrt-rail-brand"><img src="/static/images/logo-wide.png" alt="DreamingOS"></div><nav class="dwrt-rail-list" aria-label="Docker 功能">${nav()}</nav></aside>`:`<nav class="docker-tabs dwrt-kit-tabs" aria-label="Docker 功能">${nav()}</nav>`}<main class="docker-main"><div class="docker-toolbar"><h1>${NAV.find(n=>n[0]===s.view)?.[1] || '任务'}</h1>${button('tasks','任务')}${button('refresh','刷新')}</div><div class="docker-notice" role="status">${esc(s.error)}</div><div class="docker-actions" data-docker-tools></div><div class="docker-body" data-docker-body></div></main></div>`;
    renderContent();paint();
  }
  function table(columns,rows,renderRow,empty='没有项目') {
    return `<section class="docker-table-wrap dwrt-kit-table-wrap dwrt-kit-glass-surface"><div class="dwrt-kit-table-scroll"><table class="docker-table dwrt-kit-table"><thead><tr>${columns.map(x=>`<th>${x}</th>`).join('')}</tr></thead><tbody>${rows.length?rows.map(renderRow).join(''):`<tr><td colspan="${columns.length}" class="docker-empty">${esc(empty)}</td></tr>`}</tbody></table></div></section>`;
  }
  const cell=(x)=>`<td>${esc(x ?? '未上报')}</td>`;
  const unavailable=(message)=>`<div class="docker-empty">${esc(message)}</div>`;
  function monitorMarkup() {
    if(s.monitorError)return unavailable('监控读取失败：'+s.monitorError);
    if(!s.monitor.length)return unavailable(caps().stats_aggregate?'等待运行中容器的有效采样。':'引擎当前不能提供监控采样。');
    const metrics=[['cpu','CPU（100% = 一个逻辑 CPU）',v=>v.toFixed(2)+'%'],['memory','容器内存合计',bytes],['rx','网络接收',v=>bytes(v)+'/s'],['tx','网络发送',v=>bytes(v)+'/s']];
    return '<div class="docker-monitor">'+metrics.map(([key,label,format])=>{
      const valid=s.monitor.filter(p=>Number.isFinite(p[key]));
      if(!valid.length)return `<section class="docker-metric dwrt-kit-glass-surface"><span>${label}</span><p>等待有效采样</p></section>`;
      const last=valid.at(-1),max=Math.max(...valid.map(p=>p[key]),1),first=s.monitor[0].ts,span=Math.max(s.monitor.at(-1).ts-first,5);
      let drawing='',segment=[];
      const flush=()=>{if(segment.length>1)drawing+=`<polyline points="${segment.join(' ')}"/>`;segment=[];};
      for(const p of s.monitor){if(!Number.isFinite(p[key])){flush();continue;}segment.push(`${((p.ts-first)/span*300+4).toFixed(2)},${(76-p[key]/max*70).toFixed(2)}`);}flush();
      const x=((last.ts-first)/span*300+4).toFixed(2),y=(76-last[key]/max*70).toFixed(2);
      return `<section class="docker-metric dwrt-kit-glass-surface"><span>${label}</span><strong>${esc(format(last[key]))}</strong><svg class="docker-trend" viewBox="0 0 308 82" role="img" aria-label="${esc(label+'，'+valid.length+'个有效样本')}">${drawing}<circle cx="${x}" cy="${y}" r="2.5"/></svg><small>${new Date(first*1000).toLocaleTimeString()} — ${new Date(last.ts*1000).toLocaleTimeString()}</small></section>`;
    }).join('')+'</div>';
  }
  function visible() {
    if(document.hidden||!root.getClientRects().length)return false;
    try {if(window.frameElement&&!window.frameElement.getClientRects().length)return false;}catch(_){}
    return true;
  }
  async function sampleMonitor() {
    if(!s.alive||s.statsLoading||!visible()||s.view!=='overview'||s.sheet||!caps().stats_aggregate)return;
    s.statsLoading=true;
    try {
      const data=await request('/stats');if(!s.alive)return;
      const rows=data.samples||[],key=rows.map(p=>p.id).sort().join(','),ts=Number(data.ts);
      if(key!==s.monitorKey){s.monitor=[];s.previousSample=null;s.monitorKey=key;}
      if(!rows.length){s.monitor=[];s.monitorError='';s.previousSample=null;return;}
      if(s.previousSample?.ts===ts)return;
      const sum=field=>rows.every(p=>Number.isFinite(p[field]))?rows.reduce((v,p)=>v+p[field],0):null;
      const point={ts,cpu:sum('cpu_percent'),memory:sum('memory_usage_bytes'),rx:null,tx:null};
      const rx=sum('network_rx_bytes'),tx=sum('network_tx_bytes'),prev=s.previousSample;
      if(prev&&ts>prev.ts&&ts-prev.ts<=20) {
        if(rx!=null&&prev.rx!=null&&rx>=prev.rx)point.rx=(rx-prev.rx)/(ts-prev.ts);
        if(tx!=null&&prev.tx!=null&&tx>=prev.tx)point.tx=(tx-prev.tx)/(ts-prev.ts);
      }
      s.previousSample={ts,rx,tx};s.monitor.push(point);s.monitor=s.monitor.slice(-60);s.monitorError='';
    }catch(error){if(s.alive)s.monitorError=error.message;}
    finally {s.statsLoading=false;if(s.alive&&s.view==='overview'&&!s.sheet){const node=root.querySelector('[data-monitor]');if(node)node.innerHTML=monitorMarkup();}}
  }
  function renderContent() {
    const main=root.querySelector('.docker-main');
    if(!main)return;
    if(kit?.preserveInteractionState)kit.preserveInteractionState(main,target=>{
      target.innerHTML=main.innerHTML;
      renderContentInto(target);
    });
    else renderContentInto(main);
  }
  function renderContentInto(target) {
    const body=target.querySelector('[data-docker-body]'), tools=target.querySelector('[data-docker-tools]');
    if(!body)return;
    const scroll=[body.scrollTop,body.scrollLeft],d=s.data;
    tools.innerHTML='';
    if(!d){body.innerHTML=unavailable(s.error?'暂时无法读取 Docker。可点击刷新重试。':'正在读取 Docker…');return;}
    const runtime=d.runtime?.state || (!d.available?'not_installed':d.service?.running?'ready':'stopped');
    if(s.view==='overview') {
      const values=[['引擎状态',LABEL[runtime]||runtime],['容器',d.counts?.containers],['运行中',d.counts?.running],['镜像',d.counts?.images]];
      body.innerHTML=`<div class="docker-overview">${values.map(([label,value])=>`<section class="docker-metric dwrt-kit-glass-surface"><span>${label}</span><strong>${esc(value ?? '未读取')}</strong></section>`).join('')}</div><dl class="docker-info"><dt>引擎版本</dt><dd>${esc(d.info?.version || '未读取')}</dd><dt>架构</dt><dd>${esc(d.info?.architecture || '未读取')}</dd><dt>存储驱动</dt><dd>${esc(d.info?.storage_driver || '未读取')}</dd><dt>数据位置</dt><dd>${esc(d.info?.data_root || '未读取')}</dd></dl>${Object.entries(d.read_errors||{}).map(([k,v])=>unavailable(`${k} 读取失败：${describe(v)}`)).join('')}<div data-monitor>${monitorMarkup()}</div>`;
    } else if(s.view==='containers') {
      tools.innerHTML=`<span class="dwrt-kit-field docker-search"><input class="dwrt-kit-input" data-docker-search placeholder="搜索容器" aria-label="搜索容器" value="${esc(s.query)}"></span><select class="dwrt-kit-select" data-docker-filter aria-label="容器状态"><option value="">全部状态</option>${['running','exited','paused','created'].map(x=>`<option value="${x}" ${s.filter===x?'selected':''}>${LABEL[x]}</option>`).join('')}</select>${button('create','创建容器','container_create')}`;
      const rows=(d.containers||[]).filter(x=>(!s.filter||s.filter===x.state)&&JSON.stringify(x).toLowerCase().includes(s.query.toLowerCase()));
      body.innerHTML=table(['选择','名称','镜像','状态','端口','操作'],rows,x=>`<tr><td><input type="checkbox" data-docker-select="${esc(x.id)}" aria-label="选择 ${esc(x.name)}" ${s.selected.has(x.id)?'checked':''}></td><td><span class="docker-name"><strong>${esc(x.name)}</strong><small>${esc(x.id?.slice(0,12))}</small></span></td>${cell(x.image)}${cell(LABEL[x.state]||x.status)}${cell(x.ports||'未映射')}<td>${button('detail','详情','','medium',`data-kind="container" data-id="${esc(x.id)}"`)}</td></tr>`,d.read_errors?.containers?'容器读取失败':runtime==='ready'?'没有容器':'引擎尚不可用');
    } else if(['images','networks','volumes'].includes(s.view)) {
      const kind={images:'image',networks:'network',volumes:'volume'}[s.view];
      tools.innerHTML=s.view==='images'?button('pull','拉取镜像','image_pull','high')+button('load-image','导入 tar','image_load','high'):button('new-'+kind,s.view==='networks'?'创建网络':'创建卷',kind+'_create');
      const rows=d[s.view]||[];
      body.innerHTML=table(s.view==='images'?['仓库 / 标签','大小','ID','操作']:['名称','驱动',s.view==='networks'?'作用域':'挂载点','操作'],rows,x=>`<tr>${cell(s.view==='images'?`${x.repository}:${x.tag}`:x.name)}${cell(s.view==='images'?x.size:x.driver)}${cell(s.view==='images'?x.id:s.view==='networks'?x.scope:x.mountpoint)}<td><div class="docker-actions">${button('detail','详情','','medium',`data-kind="${kind}" data-id="${esc(x.id||x.name)}"`)}${s.view==='images'?button('from-image','创建容器','container_create','medium',`data-image="${esc(x.id)}"`):''}${kind==='network'&&!['bridge','host','none'].includes(x.name)?button('edit-network','编辑重建','network_recreate','high',`data-id="${esc(x.id)}"`):''}${button('remove','删除',kind+'_remove','high',`data-kind="${kind}" data-id="${esc(x.id||x.name)}"`)}</div></td></tr>`,d.read_errors?.[s.view]?'读取失败，请刷新重试':'没有项目');
    } else if(s.view==='registry') {
      tools.innerHTML=(caps().registry_search?`<input class="dwrt-kit-input docker-search" data-registry-keyword aria-label="仓库关键词" placeholder="搜索 Docker Hub" value="${esc(s.registryKeyword)}">${button('search-registry','搜索')}`:'')+button('pull','按镜像引用拉取','image_pull','high');
      body.innerHTML=!caps().registry_search?unavailable('当前未提供公共仓库搜索。仍可按镜像引用拉取。'):!s.registry?unavailable('输入关键词搜索 Docker Hub 公共镜像。'):s.registry.error?unavailable(s.registry.error):table(['镜像','说明','热度','操作'],s.registry.items||[],x=>`<tr>${cell(x.name+(x.official?' · 官方':''))}${cell(x.description)}${cell(x.stars)}<td>${button('pull-result','拉取','image_pull','high',`data-image="${esc(x.name)}"`)}</td></tr>`,'没有匹配的镜像')+`<div class="docker-actions"><span>Docker Hub · 第 ${s.registryPage} 页 · 本次最多返回 ${s.registry.result_limit} 项</span>${s.registryPage>1?button('registry-prev','上一页'):''}${s.registry.has_more?button('registry-next','下一页'):''}</div>`;
    } else if(s.view==='compose') {
      tools.innerHTML=button('new-compose','新建项目','compose','high')+button('import-compose','导入设备 YAML','compose','high');
      body.innerHTML=s.projectError?unavailable(s.projectError):!caps().compose?unavailable('目标设备没有可用的 Docker Compose 工具。'):table(['项目','来源','服务','操作'],s.projects,x=>`<tr>${cell(x.name)}${cell(x.managed?'工作台管理':'外部项目（只读）')}${cell(x.services?.map(v=>(v.name||v.id)+': '+(LABEL[v.state]||v.state)).join('、')||'未运行')}<td>${x.managed?button('compose-detail','管理','compose','high',`data-id="${esc(x.id)}"`):'由原安装入口管理'}</td></tr>`,'没有 Compose 项目');
    }
    else if(s.view==='settings') {
      tools.innerHTML=['start','stop','restart','reload'].map(x=>button('service-'+x,{start:'启动引擎',stop:'停止引擎',restart:'重启引擎',reload:'重载引擎'}[x],'service_action','high')).join('')+button('cleanup-preview','清理空间','cleanup_preview','high');
      body.innerHTML=engineSettingsMarkup();
    } else if(s.view==='tasks') {
      body.innerHTML=table(['类型','目标','状态','操作'],s.jobs,x=>`<tr>${cell({container_create:'创建容器',image_pull:'拉取镜像',image_load:'导入镜像',compose_action:'Compose 操作',container_clone:'克隆容器',container_recreate:'重建容器',container_recover:'恢复原容器',docker_cleanup:'清理空间',docker_config:'引擎设置'}[x.kind]||x.kind)}${cell(x.target)}${cell(LABEL[x.state]||x.state)}<td>${button('job','查看','','medium',`data-id="${esc(x.job_id)}"`)} ${['queued','running'].includes(x.state)?button('cancel-job','取消','async_tasks','high',`data-id="${esc(x.job_id)}"`):''}</td></tr>`, '没有任务记录');
    }
    body.scrollTop=scroll[0];body.scrollLeft=scroll[1];
  }
  async function refresh() {
    if(!s.alive||s.refreshing)return;
    s.refreshing=true;
    try {
      const [dataResult,jobsResult]=await Promise.allSettled([request(),request('/jobs?limit=30')]);
      if(!s.alive)return;
      if(dataResult.status==='rejected')throw dataResult.reason;
      const data=dataResult.value,jobs=jobsResult.status==='fulfilled'?jobsResult.value:null;
      const signature=JSON.stringify({data,jobs},(key,value)=>key==='ts'?undefined:value);const changed=signature!==s.signature;s.signature=signature;s.data=data;if(jobs)s.jobs=jobs.jobs||jobs.items||[];s.error=jobsResult.status==='rejected'?'任务读取失败：'+jobsResult.reason.message:'';
      if(s.view==='compose'&&data.capabilities?.compose) {
        try {const projects=await request('/compose');s.projects=projects.projects||[];s.projectError=projects.runtime_error?'项目配置可读，但运行状态读取失败。':'';}
        catch(error){s.projectError=error.message;}
      }
      if(s.view==='settings') {
        try {s.engineSettings=await request('/config');s.engineError='';}
        catch(error){s.engineError=error.message;}
      }
      // No form, focus or selection replacement while the user is interacting.
      const contentFocused=['[data-docker-body]','[data-docker-tools]'].some(selector=>root.querySelector(selector)?.contains(document.activeElement));
      if((changed||['compose','settings'].includes(s.view))&&!s.sheet&&!contentFocused)renderContent();
      root.querySelector('.docker-notice').textContent=s.error;
    } catch(error){if(s.alive){s.error=error.message;root.querySelector('.docker-notice').textContent=s.error;}}
    finally{s.refreshing=false;sampleMonitor();}
  }
  function confirm(title,description) {
    if(s.confirm)return Promise.resolve(false);
    const node=document.createElement('div');node.dataset.dockerOwner=id;
    node.innerHTML=kit.confirmationMarkup({id:id+'-confirm',tone:'warning',title,description,confirmLabel:'确认'});document.body.append(node);
    const previous=document.activeElement;
    return new Promise(resolve=>{
      const finish=answer=>{node.remove();s.confirm=null;previous?.focus?.({preventScroll:true});resolve(answer);};
      s.confirm={node,finish};
      node.addEventListener('click',e=>{if(e.target.closest('[data-dwrt-confirm-accept]'))finish(true);else if(e.target.closest('[data-dwrt-confirm-cancel]'))finish(false);});
      node.querySelector('[data-dwrt-confirm-cancel]').focus();
    });
  }
  async function closeSheet(force=false) {
    if(!s.sheet)return true;
    if(s.busy&&!force)return false;
    if(!force&&s.sheet.dirty&&!await confirm('放弃尚未提交的内容？','当前表单内容将被丢弃。'))return false;
    s.sheet.terminal?.close();
    s.sheet.host.append(s.sheet.element,s.sheet.overlay);
    kit?.unmount?.(s.sheet.host);s.sheet.host.remove();s.sheet=null;return true;
  }
  async function sheet(title,content,footer='',form=false,wide=false) {
    if(!await closeSheet())return;
    const node=document.createElement('div');node.dataset.dockerOwner=id;document.body.append(node);
    node.innerHTML=`<button class="dwrt-kit-sheet-overlay is-open" data-docker-owner="${id}" data-docker-action="close-sheet" aria-label="关闭"></button><aside class="dwrt-kit-sheet docker-sheet is-open" data-docker-owner="${id}" data-dwrt-component="sheet" data-dwrt-sheet-size="${form&&!wide?'form':'wide'}" aria-label="${esc(title)}"><header class="dwrt-kit-sheet-header"><strong>${esc(title)}</strong><button class="dwrt-kit-sheet-close" data-docker-action="close-sheet" aria-label="关闭">×</button></header><div class="dwrt-kit-sheet-body"><div class="docker-form">${content}</div><p class="docker-sheet-error" role="alert"></p></div><footer class="dwrt-kit-sheet-footer docker-actions">${footer}</footer></aside>`;
    const element=node.querySelector('aside'),overlay=node.querySelector('.dwrt-kit-sheet-overlay');
    s.sheet={host:node,element,overlay,dirty:false,form};kit?.mountAll?.(node);element.querySelector('input,textarea,button')?.focus();
  }
  const field=(name,label,value='',type='text',extra='')=>`<label class="dwrt-kit-field" data-dwrt-component="field">${esc(label)}<input class="dwrt-kit-input" name="${name}" type="${type}" value="${esc(value)}" ${extra}></label>`;
  const textfield=(name,label,value='')=>`<label class="dwrt-kit-field" data-dwrt-component="field">${esc(label)}<textarea class="dwrt-kit-textarea" name="${name}">${esc(value)}</textarea></label>`;
  function portRow(){return `<div class="docker-repeat" data-port><div class="docker-field-row">${field('host_port','宿主端口','','number','min="1" max="65535" required')}${field('container_port','容器端口','','number','min="1" max="65535" required')}${field('host_ip','宿主 IP（可选）')}<label class="dwrt-kit-field" data-dwrt-component="field">协议<select class="dwrt-kit-select" name="protocol"><option>tcp</option><option>udp</option></select></label></div>${button('remove-row','移除映射')}</div>`;}
  function mountRow(){return `<div class="docker-repeat" data-mount><label class="dwrt-kit-field" data-dwrt-component="field">挂载类型<select class="dwrt-kit-select" name="type"><option value="volume">Docker 卷</option><option value="bind">设备目录</option></select></label>${field('source','已有卷名称 / 设备目录绝对路径')}${field('target','容器内目录')}<label class="docker-check"><input type="checkbox" name="read_only">只读</label>${button('remove-row','移除挂载')}</div>`;}
  async function create(image='',seed=null,replacement=null) {
    const extended=caps().create_ports;
    await sheet(replacement?.mode==='recreate'?'修改并重建容器':replacement?'克隆容器':'创建容器',`${field('name','名称')}${field('image','镜像',image,'text','required')}<label class="dwrt-kit-field" data-dwrt-component="field">重启策略<select class="dwrt-kit-select" name="restart_policy"><option value="no">不自动重启</option><option value="unless-stopped">除非手动停止</option><option value="always">始终</option><option value="on-failure">失败时</option></select></label>${field('network','网络','bridge')}${textfield('command','命令参数（每行一项，可留空）')}${extended?`<strong>端口映射</strong><div data-ports></div>${button('add-port','添加端口')}<strong>持久数据</strong><div data-mounts></div>${button('add-mount','添加挂载')}${textfield('env','环境变量（每行 KEY=VALUE）')}<div class="docker-field-row">${field('memory','内存上限 MiB（留空不限制）','','number','min="6"')}${field('cpu_shares','CPU 权重（留空使用默认值）','','number','min="2" max="262144"')}</div>`:`<p class="docker-muted">当前引擎接口尚不支持端口、挂载与环境变量；需更新后端后使用这些参数。</p>`}`,(replacement?.mode==='recreate'?button('submit-create','预览重建','container_recreate','high'):button('submit-create','仅创建','container_create')+(caps().start_after_create?button('submit-start','创建并启动','container_create'):'')),true);
    if(seed&&s.sheet) {
      s.sheet.seed=structuredClone(seed);s.sheet.replacement=replacement;
      const el=s.sheet.element;
      if(seed.restart_policy?.startsWith('on-failure:')){const option=document.createElement('option');option.value=seed.restart_policy;option.textContent='失败时（最多 '+seed.restart_policy.split(':')[1]+' 次）';el.querySelector('[name=restart_policy]').append(option);}
      for(const key of ['name','image','network','restart_policy']){const input=el.querySelector(`[name=${key}]`);if(input)input.value=seed[key]||'';}
      el.querySelector('[name=command]').value=(seed.command||[]).join('\n');
      el.querySelector('[name=env]').value=Object.entries(seed.env||{}).map(([k,v])=>k+'='+v).join('\n');
      el.querySelector('[name=memory]').value=seed.resources?.memory_bytes?seed.resources.memory_bytes/1048576:'';
      el.querySelector('[name=cpu_shares]').value=seed.resources?.cpu_shares||'';
      for(const port of seed.ports||[]){const list=el.querySelector('[data-ports]');list.insertAdjacentHTML('beforeend',portRow());for(const [key,v] of Object.entries(port)){const input=list.lastElementChild.querySelector(`[name=${key}]`);if(input)input.value=v;}}
      for(const mount of seed.mounts||[]){const list=el.querySelector('[data-mounts]');list.insertAdjacentHTML('beforeend',mountRow());for(const [key,v] of Object.entries(mount)){const input=list.lastElementChild.querySelector(`[name=${key}]`);if(input){if(input.type==='checkbox')input.checked=v;else input.value=v;}}}
      if(replacement.mode==='recreate')el.querySelector('[name=name]').readOnly=true;
      el.querySelector('.docker-form').insertAdjacentHTML('afterbegin',`<p>${replacement.mode==='clone'?'克隆会沿用所填挂载，不复制卷内数据；宿主端口需避开原容器。':'重建会中断此容器服务。验证成功后原容器保留为备份，失败时尝试恢复。'}</p>`);
    }
  }
  function createPayload(start) {
    const el=s.sheet.element,get=name=>el.querySelector(`[name="${name}"]`)?.value || '';
    const payload={...(s.sheet.seed||{}),image:get('image'),restart_policy:get('restart_policy'),confirm:true};
    if(get('name'))payload.name=get('name');if(get('network'))payload.network=get('network');
    if(get('command'))payload.command=get('command').split('\n');else if(s.sheet.seed)payload.command=[];
    if(caps().create_ports) {
      payload.start_after_create=start;
      payload.ports=[...el.querySelectorAll('[data-port]')].map(row=>{const v=n=>row.querySelector(`[name="${n}"]`).value;return {host_port:Number(v('host_port')),container_port:Number(v('container_port')),protocol:v('protocol'),...(v('host_ip')?{host_ip:v('host_ip')}:{})};});
      payload.mounts=[...el.querySelectorAll('[data-mount]')].map(row=>{const v=n=>row.querySelector(`[name="${n}"]`);return {type:v('type').value,source:v('source').value,target:v('target').value,read_only:v('read_only').checked};});
      const env={};for(const line of get('env').split('\n').filter(Boolean)){const at=line.indexOf('=');if(at<=0)throw new Error('环境变量必须使用 KEY=VALUE');const k=line.slice(0,at);if(Object.hasOwn(env,k))throw new Error('环境变量名称重复：'+k);Object.defineProperty(env,k,{value:line.slice(at+1),enumerable:true});}payload.env=env;
      payload.resources={};if(get('memory'))payload.resources.memory_bytes=Number(get('memory'))*1048576;if(get('cpu_shares'))payload.resources.cpu_shares=Number(get('cpu_shares'));
    }
    return payload;
  }
  async function mutate(path,method,payload={}) {
    if(s.busy)return;
    s.busy=true;
    const current=s.sheet;
    current?.element.querySelectorAll('button').forEach(b=>b.disabled=true);
    try {
      const result=await request(path,method,{...payload,confirm:true});
      await closeSheet(true);
      if(result.job_id){s.view='tasks';s.query='';render();}
      await refresh();renderContent();
      if(result.job_id)root.querySelector('.docker-notice').textContent='任务已受理，完成状态以任务结果为准。';
    } catch(error){if(s.sheet)s.sheet.element.querySelector('.docker-sheet-error').textContent=error.message;else root.querySelector('.docker-notice').textContent=error.message;}
    finally{s.busy=false;current?.element.querySelectorAll('button').forEach(b=>b.disabled=false);if(!s.sheet){const notice=root.querySelector('.docker-notice').textContent;render();root.querySelector('.docker-notice').textContent=notice;}}
  }
  async function detail(kind,target) {
    if(!caps()[kind+'_inspect']){await sheet('详情',unavailable('当前引擎接口尚未提供此对象详情。'));return;}
    const d=await request(`/${kind}/${encodeURIComponent(target)}`);
    let actions='';
    if(kind==='container'){
      const state=d.state?.Status;
      const allowed={start:['created','exited'],stop:['running'],restart:['running','exited'],pause:['running'],unpause:['paused']};
      actions=Object.entries(allowed).filter(([,states])=>states.includes(state)).map(([a])=>button('container-'+a,{start:'启动',stop:'停止',restart:'重启',pause:'暂停',unpause:'恢复'}[a],'container_'+a,'medium',`data-id="${esc(target)}"`)).join('');
      if(!d.source?.compose_project)actions+=button('clone','克隆','container_clone','high',`data-id="${esc(target)}"`)+button('recreate','修改 / 重建','container_recreate','high',`data-id="${esc(target)}"`);
      actions+=button('logs','日志','', 'medium',`data-id="${esc(target)}"`)+button('stats','监控','','medium',`data-id="${esc(target)}"`)+button('rename','重命名','container_rename','medium',`data-id="${esc(target)}"`)+button('policy','重启策略','container_restart_policy','medium',`data-id="${esc(target)}"`)+button('remove','删除','container_remove','high',`data-kind="container" data-id="${esc(target)}"`);
      if(state==='running')actions+=button('terminal','终端','','medium',`data-id="${esc(d.id)}" ${authorized()?'':'disabled title="当前账号没有终端权限"'}`);
    }
    const rows=kind==='container'?[['名称',d.name],['ID',d.id],['镜像',d.image],['状态',LABEL[d.state?.Status]||d.state?.Status],['环境变量名称',(d.env_keys||[]).join(', ')],['端口',JSON.stringify(d.ports,null,2)],['挂载',JSON.stringify(d.mounts,null,2)],['网络',JSON.stringify(d.networks,null,2)],['资源',JSON.stringify(d.resources,null,2)]]:Object.entries(d).filter(([key])=>!['ok','ts'].includes(key));
    await sheet(kind==='container'?'容器详情':kind==='image'?'镜像详情':kind==='network'?'网络详情':'卷详情',`<dl class="docker-info">${rows.map(([key,v])=>`<dt>${esc(key)}</dt><dd><pre class="docker-log">${esc(typeof v==='object'?JSON.stringify(v,null,2):v)}</pre></dd>`).join('')}</dl>`,actions);
  }
  async function terminal(containerId) {
    const capability=await request('/terminal/capabilities');
    const module=await import('./docker-terminal.js?v='+VERSION);
    if(!s.alive)return;
    if(!capability.terminal||!capability.connect){
      await sheet('容器终端',unavailable(module.terminalReason(capability.reason)));return;
    }
    await sheet('容器终端',`<p class="docker-muted">${esc(containerId.slice(0,12))} · 关闭此面板会结束终端会话。</p><div class="docker-terminal-tools"><label class="dwrt-kit-field">Shell<select class="dwrt-kit-select" data-terminal-shell>${(capability.shells||[]).map(shell=>`<option>${esc(shell)}</option>`).join('')}</select></label><button class="dwrt-kit-button" data-dwrt-component="button" data-terminal-connect>连接</button><button class="dwrt-kit-button" data-dwrt-component="button" data-terminal-disconnect disabled>断开</button></div><p class="docker-terminal-state" data-terminal-state role="status"></p><div class="docker-terminal-pane" data-container-terminal aria-label="容器交互终端"></div>`);
    if(!s.sheet)return;
    s.sheet.element.classList.add('docker-terminal-sheet');
    s.sheet.terminal=module.mountTerminal({element:s.sheet.element,containerId,workspace:id,request});
  }
  async function registrySearch(page=1) {
    const keyword=root.querySelector('[data-registry-keyword]')?.value || s.registryKeyword;
    s.registryKeyword=keyword;s.registryPage=page;
    try{s.registry=await request('/registry/search?'+new URLSearchParams({keyword,page,page_size:20}));}
    catch(error){s.registry={error:error.message};}
    renderContent();
  }
  function jobMarkup(job) {
    const {transfer,...result}=job.result||{};
    const statuses={'Pulling fs layer':'等待下载',Waiting:'等待下载',Downloading:'下载中','Verifying Checksum':'校验中','Download complete':'下载完成',Extracting:'解压中','Pull complete':'完成','Already exists':'已存在'};
    const measured=(current,total)=>`${bytes(current)} / ${bytes(total)}`;
    const layers=transfer?`<p>${esc(transfer.error||transfer.status||'等待引擎进度')}${job.state==='cancelled'?' · 已取消，以下为最后一次读数；已下载层可能保留。':''}</p>`+table(['镜像层','阶段','已下载 / 总量','已解压 / 总量'],transfer.layers||[],layer=>`<tr>${cell(layer.id)}${cell(statuses[layer.status]||layer.status)}${cell(measured(layer.downloaded_bytes,layer.download_total_bytes))}${cell(measured(layer.extracted_bytes,layer.extract_total_bytes))}</tr>`,'等待引擎返回镜像层')+(transfer.layers_truncated?'<p>仅显示前 256 个镜像层。</p>':''):'';
    const migration=job.kind==='docker_migration';
    const phases={stopping:'停止服务',copying:'复制数据',verifying:'校验数据',switching:'切换目录',starting:'启动并验证',restoring:'恢复原目录',restored:'已恢复原目录',recovery_required:'等待恢复',complete:'迁移完成'};
    const progress=migration?`<dl class="docker-info"><dt>迁移阶段</dt><dd>${esc(phases[result.phase]||result.phase||'等待执行')}</dd><dt>源目录</dt><dd>${esc(result.source||'未读取')}</dd><dt>目标目录</dt><dd>${esc(result.target||'未读取')}</dd><dt>已传输数据</dt><dd>${bytes(result.copied_bytes)}</dd><dt>已传输文件</dt><dd>${esc(result.copied_files??'未上报')}</dd><dt>扫描总量</dt><dd>${bytes(result.total_bytes)} · ${esc(result.total_files??'未上报')} 个条目</dd><dt>恢复结果</dt><dd>${result.rollback==='restored'?'已恢复原目录':result.rollback==='failed'?'恢复未完成，请到设置再次恢复':'原目录保留'}</dd></dl>`:'';
    return `${progress}<dl class="docker-info"><dt>状态</dt><dd>${esc(LABEL[job.state]||job.state)}</dd><dt>错误</dt><dd>${esc(job.error||'无')}</dd><dt>结果</dt><dd>${esc(JSON.stringify(result))}</dd></dl>${layers}<pre class="docker-log">${esc(job.output||'')}${job.output_truncated?'\n[输出已截断]':''}</pre>`;
  }
  async function refreshPullJob() {
    const current=s.sheet;
    if(!current?.pullJob||current.readingJob||!visible())return;
    current.readingJob=true;
    try {
      const job=await request('/jobs/'+encodeURIComponent(current.pullJob));
      if(!s.alive||s.sheet!==current)return;
      const content=jobMarkup(job);
      if(content!==current.jobContent){current.element.querySelector('[data-job-detail]').innerHTML=content;current.jobContent=content;}
      if(!['queued','running'].includes(job.state))current.pullJob=null;
    }catch(error){if(s.sheet===current)current.element.querySelector('.docker-sheet-error').textContent=error.message;}
    finally{current.readingJob=false;}
  }
  function engineSettingsMarkup() {
    const cfg=s.engineSettings,d=s.data;
    if(s.engineError)return unavailable('引擎设置读取失败：'+s.engineError);
    if(!cfg)return unavailable('正在读取引擎设置…');
    const active=s.jobs.some(j=>['docker_config','docker_migration'].includes(j.kind)&&['queued','running'].includes(j.state));
    const recovery=cfg.state&&cfg.state!=='idle';
    const migration=cfg.state?.startsWith('migration_');
    const status=active?(migration?'数据迁移正在处理':'正在应用或恢复'):recovery?(migration?'数据迁移未完成，等待恢复':'上次应用未完成，等待恢复'):cfg.external_change?'设备配置有外部修改':cfg.pending_apply?'已保存，待应用':'已应用';
    const mirrors=list=>list?.length?list.join('、'):'未设置';
    const last=cfg.last_result||{};
    return `<dl class="docker-info"><dt>服务</dt><dd>${d.service?.running?'运行中':'已停止'}</dd><dt>配置状态</dt><dd>${esc(status)}</dd><dt>已保存镜像源</dt><dd>${esc(mirrors(cfg.config?.registry_mirrors))}</dd><dt>已应用镜像源</dt><dd>${esc(mirrors(cfg.applied_config?.registry_mirrors))}</dd><dt>开机启动</dt><dd>已保存：${cfg.config?.autostart?'启用':'关闭'} · 设备：${cfg.runtime_config?.autostart?'启用':'关闭'}</dd><dt>数据位置</dt><dd>${esc(cfg.data_root||d.info?.data_root||'未读取')}</dd></dl>${!cfg.config_write?unavailable(describe({reason:cfg.reason})):''}${cfg.external_change?unavailable('设备设置与上次应用记录不一致。请核对外部修改后再应用。'):''}${last.error?unavailable(describe(last)+(last.rollback==='restored'?'；已恢复上次配置。':last.rollback==='failed'?'；恢复失败，请再次恢复并检查任务。':'')):''}<div class="docker-actions">${button('edit-settings','编辑引擎设置','config_write','high',!cfg.config_write||active||recovery?'disabled':'')}${button('apply-settings','应用已保存配置','config_write','high',!cfg.config_write||!cfg.pending_apply||active||recovery||cfg.external_change?'disabled':'')}${recovery?button(migration?'recover-storage':'recover-settings',migration?'恢复原数据目录':'恢复上次配置','config_write','high',active?'disabled':''):button('storage-picker','迁移数据目录','storage_preview','high',active||cfg.pending_apply||cfg.external_change?'disabled':'')}</div><p class="docker-muted">保存后需单独应用。修改镜像源会重启运行中的 Docker 引擎，容器服务会暂时中断；仅修改开机启动不会重启。迁移数据目录需要暂停 Docker；原目录会保留。</p>`;
  }
  async function settingsEditor() {
    const cfg=await request('/config');
    if(!cfg.config_write||cfg.state!=='idle'||!authorized('high'))throw new Error('当前不能编辑引擎设置。');
    const mirrors=(cfg.config.registry_mirrors||[]).join('\n');
    await sheet('编辑引擎设置',textfield('registry_mirrors','镜像源（每行一个，最多 8 个）',mirrors)+`<label class="dwrt-kit-field" data-dwrt-component="field">开机启动<select class="dwrt-kit-select" name="autostart"><option value="true">启用</option><option value="false">关闭</option></select></label><p class="docker-muted">填写 HTTP 或 HTTPS 地址，不含账号、密码、查询参数或片段。留空清除镜像源。保存不会重启引擎。</p>`,kit.floatingSavebarMarkup({visible:false,message:'修改待保存，保存后需单独应用',saveLabel:'保存配置',discardLabel:'撤销修改'}),true);
    s.sheet.kind='settings';s.sheet.revision=cfg.revision;
    s.sheet.element.querySelector('[name=autostart]').value=String(cfg.config.autostart);
    s.sheet.baseline={registry_mirrors:mirrors,autostart:String(cfg.config.autostart)};
  }
  async function saveSettings() {
    const current=s.sheet,el=current.element;
    const config={registry_mirrors:el.querySelector('[name=registry_mirrors]').value.split('\n').map(x=>x.trim()).filter(Boolean),autostart:el.querySelector('[name=autostart]').value==='true'};
    if(!await confirm('保存引擎设置？','配置保存后需单独应用；本次不会重启引擎。'))return;
    s.busy=true;el.querySelectorAll('input,textarea,select,button').forEach(x=>x.disabled=true);
    try {
      await request('/config','PUT',{config,revision:current.revision,confirm:true});
      const canonical=await request('/config');
      if(JSON.stringify(canonical.config.registry_mirrors)!==JSON.stringify(config.registry_mirrors)||canonical.config.autostart!==config.autostart)throw new Error('配置回读不一致，尚未确认保存。请保留草稿并核对配置。');
      s.engineSettings=canonical;current.revision=canonical.revision;
      current.baseline={registry_mirrors:canonical.config.registry_mirrors.join('\n'),autostart:String(canonical.config.autostart)};
      for(const [key,value] of Object.entries(current.baseline))el.querySelector(`[name=${key}]`).value=value;
      current.dirty=false;el.querySelector('[data-dwrt-savebar]').classList.add('is-hidden');
      const message=el.querySelector('.docker-sheet-error');message.classList.add('is-info');message.setAttribute('role','status');message.textContent='配置已保存。关闭编辑器后，选择“应用已保存配置”使其生效。';
    }catch(error){el.querySelector('.docker-sheet-error').textContent=error.message;}
    finally{s.busy=false;el.querySelectorAll('input,textarea,select,button').forEach(x=>x.disabled=false);}
  }
  async function applySettings(recover=false) {
    const cfg=await request('/config');
    if(!authorized('high')||!cfg.config_write)throw new Error('当前不能应用引擎设置。');
    const restart=s.data?.service?.running&&JSON.stringify(cfg.config.registry_mirrors)!==JSON.stringify(cfg.runtime_config.registry_mirrors);
    const description=recover?'将恢复上次备份的引擎配置和开机启动状态；如需重启 Docker，容器服务会暂时中断。':restart?'应用已保存的镜像源需要重启 Docker 引擎，容器服务会暂时中断。': '应用已保存的设置；仅修改开机启动不会重启引擎。';
    if(await confirm(recover?'恢复上次引擎配置？':'应用引擎设置？',description))await mutate(recover?'/config/recover':'/config/apply','POST',{revision:cfg.revision,allow_restart:recover||Boolean(restart)});
  }
  async function composeEditor(projectId='') {
    const config=projectId?await request(`/compose/${encodeURIComponent(projectId)}/config`):{project:{id:'',name:'',revision:0},yaml:''};
    const footer=button('validate-compose','校验 YAML','compose','high')+kit.floatingSavebarMarkup({visible:false,message:'保存只更新项目配置，不会启动或重建服务',saveLabel:'保存配置',discardLabel:'撤销修改'});
    await sheet(projectId?'编辑 Compose 配置':'新建 Compose 项目',field('name','项目名称',config.project.name,'text','required')+field('directory','工作目录（设备目录，可留空）',config.project.directory_ref?.path||'')+'<p class="docker-muted">相对路径、Dockerfile 和环境文件以此目录为基准。导入 YAML 时默认使用文件所在目录。</p>'+textfield('yaml','Compose YAML',config.yaml),footer,true,true);
    s.sheet.project=config.project;s.sheet.baseline={name:config.project.name,yaml:config.yaml,directory:config.project.directory_ref?.path||''};
    s.sheet.element.querySelector('[name=yaml]').classList.add('docker-yaml');
  }
  async function saveCompose() {
    const current=s.sheet,el=current.element,name=el.querySelector('[name=name]').value,yaml=el.querySelector('[name=yaml]').value,directory=el.querySelector('[name=directory]').value.trim();
    if(!name||!yaml){el.querySelector('.docker-sheet-error').textContent='请填写项目名称和 YAML。';return;}
    if(!await confirm('保存 Compose 配置？','只保存，不会自动启动、停止或重建服务。'))return;
    s.busy=true;
    try {
      const project=current.project;
      const result=await request(project.id?`/compose/${encodeURIComponent(project.id)}/config`:'/compose',project.id?'PUT':'POST',{name,yaml,directory_ref:directory?{root_id:directory===current.baseline.directory?(project.directory_ref?.root_id||''):'',path:directory}:null,revision:project.revision,confirm:true});
      current.project=result.project;
      const canonical=await request(`/compose/${encodeURIComponent(result.project.id)}/config`);
      if(canonical.yaml!==yaml||canonical.project.name!==name||(canonical.project.directory_ref?.path||'')!==directory)throw new Error('配置回读不一致，尚未确认保存。');
      current.project=canonical.project;current.baseline={name,yaml,directory};current.dirty=false;
      el.querySelector('[data-dwrt-savebar]').classList.add('is-hidden');
      el.querySelector('.docker-sheet-error').classList.add('is-info');
      el.querySelector('.docker-sheet-error').setAttribute('role','status');
      el.querySelector('.docker-sheet-error').textContent='配置已保存，服务尚未应用。可回到项目管理选择启动或重建。';
      await refresh();
    }catch(error){el.querySelector('.docker-sheet-error').textContent=error.message;}
    finally{s.busy=false;}
  }
  async function composeDetail(projectId) {
    const project=s.projects.find(x=>x.id===projectId);if(!project)return;
    const ops=[['up','启动 / 应用'],['stop','停止'],['restart','重启'],['pull','拉取镜像'],...(caps().compose_build&&project.directory_ref?[['build','构建镜像']]:[]),['recreate','重建'],['delete','移除项目']];
    await sheet('Compose · '+project.name,`<dl class="docker-info"><dt>配置版本</dt><dd>${project.revision}</dd><dt>工作目录</dt><dd>${esc(project.directory_ref?.path||'未指定')}</dd><dt>服务状态</dt><dd>${esc(project.services?.map(x=>x.name+': '+(LABEL[x.state]||x.state)).join('、')||'未运行')}</dd><dt>数据保留</dt><dd>移除项目保留卷和绑定目录。重建会中断相关服务。</dd></dl>`,button('edit-compose','编辑 YAML','compose','high',`data-id="${esc(projectId)}"`)+button('compose-logs','日志','compose','high',`data-id="${esc(projectId)}"`)+ops.map(([op,label])=>button('compose-'+op,label,'compose','high',`data-id="${esc(projectId)}" data-revision="${project.revision}"`)).join(''));
  }
  async function cleanupPreview() {
    const preview=await request('/cleanup/preview'),items=preview.items||[];
    const kinds={container:'停止的容器',image:'悬空镜像',network:'未用网络',volume:'未用卷'};
    await sheet('清理空间','<p>只删除勾选的对象，卷内数据会随卷删除。共享镜像层的大小不可累加；无法计量的大小显示为未上报。</p>'+table(['选择','类型','对象','大小（估计）'],items,x=>`<tr><td><input type="checkbox" data-cleanup-index="${items.indexOf(x)}" aria-label="选择 ${esc(x.name)}"></td>${cell(kinds[x.kind])}${cell(x.name)}${cell(bytes(x.estimated_bytes))}</tr>`,'没有可清理的对象'),button('cleanup-submit','删除所选对象','cleanup_execute','high'));
    s.sheet.cleanup=items;
  }
  async function selectFile(kind,rootId='',path='/') {
    const data=await request('/api/v1/storage/files?'+new URLSearchParams({root_id:rootId,path}));
    const dirs=(data.entries||[]).filter(x=>x.is_dir||(!x.is_symlink&&(kind==='image'?/\.tar(\.gz)?$/i:kind==='storage'?/$^/:/\.ya?ml$/i).test(x.name)));
    const parent=path.replace(/\/?[^/]+\/?$/,'')||'/';
    await sheet(kind==='storage'?'选择迁移目标空目录':kind==='image'?'选择设备上的镜像归档':'选择设备上的 Compose YAML',`<div class="docker-actions">${(data.roots||[]).map(x=>button('file-dir',x.label||x.path||x.id,'','medium',`data-kind="${kind}" data-root="${esc(x.id)}" data-path="/"`)).join('')}${path!=='/'?button('file-dir','上一级','','medium',`data-kind="${kind}" data-root="${esc(data.root_id)}" data-path="${esc(parent)}"`):''}</div><p>${esc(data.path||path)}</p>`+table(['名称','大小','选择'],dirs,x=>`<tr>${cell(x.name)}${cell(x.is_dir?'目录':bytes(x.size_bytes))}<td>${button(x.is_dir?'file-dir':'file-select',x.is_dir?'打开':'选择','','medium',`data-kind="${kind}" data-root="${esc(data.root_id)}" data-path="${esc(x.path)}" data-size="${x.size_bytes}" data-mtime="${x.modified_unix}"`)}</td></tr>`,'此目录中没有符合类型的文件'),kind==='storage'?button('storage-preview','选择此目录并预检','','high',`data-root="${esc(data.root_id)}" data-path="${esc(data.path||path)}" ${authorized('high')?'':'disabled'}`):'');
  }
  async function storagePreview(rootId,path) {
    if(!authorized('high'))throw new Error('当前账号没有迁移权限。');
    const ref={root_id:rootId,path};
    const plan=await request('/storage/preview','POST',{directory_ref:ref});
    const running=(plan.inventory?.containers||[]).filter(x=>x.running);
    await sheet('数据迁移预检',`<dl class="docker-info"><dt>当前目录</dt><dd>${esc(plan.source)}</dd><dt>目标目录</dt><dd>${esc(plan.target)}</dd><dt>containerd 数据</dt><dd>${esc(plan.containerd?.root)}</dd><dt>预计数据量</dt><dd>${bytes(plan.estimated_bytes)} · ${esc(plan.estimated_files)} 个条目</dd><dt>目标空间</dt><dd>可用 ${bytes(plan.available_bytes)} · 需要 ${bytes(plan.required_bytes)}</dd></dl><p>迁移会停止 Docker 引擎及以下容器；复制与校验完成后，在新目录启动并恢复原运行状态。原目录保留。</p>`+table(['需暂停的容器','镜像'],running,x=>`<tr>${cell(x.name||x.id)}${cell(x.image)}</tr>`,'没有运行中的容器')+'<p class="docker-muted">迁移期间其他 Docker 写操作暂停。取消或中断后，可从设置恢复原数据目录。</p>',button('storage-migrate','停止 Docker 并迁移','','high',authorized('high')?'':'disabled'));
    s.sheet.migration={plan,ref};
  }
  async function storageMigrate(recover=false) {
    if(!authorized('high'))throw new Error('当前账号没有迁移权限。');
    const current=s.sheet,migration=current?.migration;
    if(!recover&&!migration)return;
    const message=recover?'将停止当前 Docker，切回保留的原数据目录并恢复原容器运行状态。迁移目标目录保留。':`将 Docker 数据从 ${migration.plan.source} 复制到 ${migration.plan.target}。迁移期间容器服务停止，完成后恢复。`;
    if(await confirm(recover?'恢复原数据目录？':'停止 Docker 并迁移？',message)){
      if(!recover&&s.sheet!==current)return;
      await mutate(recover?'/storage/recover':'/storage/migrate','POST',recover?{}:{directory_ref:migration.ref,revision:migration.plan.revision,allow_stop:true});
    }
  }
  async function handle(event) {
    const target=event.target.closest('[data-docker-action],[data-docker-view],[data-dwrt-savebar-save],[data-dwrt-savebar-discard]');if(!target)return;
    if(!root.contains(target)&&target.closest('[data-docker-owner]')?.dataset.dockerOwner!==id)return;
    if(target.disabled)return;
    // Kit portals relay bubbling clicks to their former host. Handle each command once.
    event.stopImmediatePropagation();
    if(s.sheet){const message=s.sheet.element.querySelector('.docker-sheet-error');message.classList.remove('is-info');message.setAttribute('role','alert');}
    const action=target.hasAttribute('data-dwrt-savebar-save')?(s.sheet?.kind==='settings'?'save-settings':s.sheet?.kind==='network'?'submit-network-edit':'save-compose'):target.hasAttribute('data-dwrt-savebar-discard')?'discard-compose':target.dataset.dockerAction,objectId=target.dataset.id,kind=target.dataset.kind;
    try {
      if(target.dataset.dockerView){s.view=target.dataset.dockerView;s.query='';s.filter='';render();if(['compose','settings'].includes(s.view)){await refresh();renderContent();}return;}
      if(action==='close-sheet'){event.preventDefault();event.stopImmediatePropagation();await closeSheet();return;}
      if(action==='refresh'){await refresh();renderContent();return;}
      if(action==='tasks'){s.view='tasks';render();await refresh();renderContent();return;}
      if(action==='search-registry'||action==='registry-next'||action==='registry-prev')return await registrySearch(action==='search-registry'?1:s.registryPage+(action==='registry-next'?1:-1));
      if(action==='pull-result'){await sheet('拉取镜像',field('image','镜像引用',target.dataset.image+':latest','text','required'),button('submit-pull','拉取','image_pull','high'),true);return;}
      if(action==='new-compose'||action==='edit-compose')return await composeEditor(objectId||'');
      if(action==='save-compose')return await saveCompose();
      if(action==='storage-picker')return await selectFile('storage');
      if(action==='storage-preview')return await storagePreview(target.dataset.root,target.dataset.path);
      if(action==='storage-migrate'||action==='recover-storage')return await storageMigrate(action==='recover-storage');
      if(action==='edit-settings')return await settingsEditor();
      if(action==='save-settings')return await saveSettings();
      if(action==='apply-settings'||action==='recover-settings')return await applySettings(action==='recover-settings');
      if(action==='discard-compose'){for(const [key,value] of Object.entries(s.sheet.baseline)){const el=s.sheet.element.querySelector(`[name=${key}]`);if(el.type==='checkbox')el.checked=value;else el.value=value;}s.sheet.dirty=false;s.sheet.element.querySelector('[data-dwrt-savebar]').classList.add('is-hidden');return;}
      if(action==='validate-compose'){await request('/compose/validate','POST',{yaml:s.sheet.element.querySelector('[name=yaml]').value,directory_ref:s.sheet.element.querySelector('[name=directory]').value.trim()?{root_id:s.sheet.project.directory_ref?.root_id||'',path:s.sheet.element.querySelector('[name=directory]').value.trim()}:null,confirm:true});s.sheet.element.querySelector('.docker-sheet-error').classList.add('is-info');s.sheet.element.querySelector('.docker-sheet-error').setAttribute('role','status');s.sheet.element.querySelector('.docker-sheet-error').textContent='YAML 校验通过；尚未保存或应用。';return;}
      if(action==='compose-detail')return await composeDetail(objectId);
      if(action==='compose-logs'){const logs=await request(`/compose/${encodeURIComponent(objectId)}/logs`);await sheet('项目日志',`<pre class="docker-log">${esc(logs.logs)}${logs.output_truncated?'\n[输出已截断]':''}</pre>`,button('compose-logs','刷新','compose','high',`data-id="${esc(objectId)}"`));return;}
      if(action?.startsWith('compose-')){const op=action.slice(8);if(await confirm('执行项目操作？',`${target.textContent}会影响项目服务。卷和绑定目录中的数据保留。`))return await mutate(`/compose/${encodeURIComponent(objectId)}${op==='delete'?'':'/'+op}`,op==='delete'?'DELETE':'POST',{revision:Number(target.dataset.revision)});return;}
      if(action==='cleanup-preview')return await cleanupPreview();
      if(action==='cleanup-submit'){
        const items=[...s.sheet.element.querySelectorAll('[data-cleanup-index]:checked')].map(el=>s.sheet.cleanup[Number(el.dataset.cleanupIndex)]);
        if(!items.length){s.sheet.element.querySelector('.docker-sheet-error').textContent='请选择要删除的对象。';return;}
        if(await confirm('删除所选对象？',items.map(x=>x.name).join('、')+'。所选卷中的数据会删除；对象引用变化时停止相应删除。'))return await mutate('/cleanup','POST',{items:items.map(({kind,id,revision})=>({kind,id,revision}))});
        return;
      }
      if(action==='load-image'||action==='import-compose')return await selectFile(action==='load-image'?'image':'compose');
      if(action==='file-dir')return await selectFile(kind,target.dataset.root,target.dataset.path);
      if(action==='file-select'){
        const file_ref={root_id:target.dataset.root,path:target.dataset.path,size_bytes:Number(target.dataset.size),modified_unix:Number(target.dataset.mtime)};
        if(kind==='image'){if(await confirm('导入镜像归档？',file_ref.path+'。导入会占用 Docker 数据空间。'))return await mutate('/image/load','POST',{file_ref});}
        else {await sheet('导入 Compose 项目',field('name','项目名称','','text','required')+`<p>${esc(file_ref.path)}</p>`,button('submit-compose-file','导入配置','compose','high'),true);s.sheet.fileRef=file_ref;}
        return;
      }
      if(action==='submit-compose-file'){const name=s.sheet.element.querySelector('[name=name]').value;if(name&&await confirm('导入项目配置？','校验并保存 YAML，服务不会自动启动。'))return await mutate('/compose/import','POST',{name,file_ref:s.sheet.fileRef});return;}
      if(action==='create'||action==='from-image')return await create(target.dataset.image);
      if(action==='add-port'){s.sheet.element.querySelector('[data-ports]').insertAdjacentHTML('beforeend',portRow());s.sheet.dirty=true;return;}
      if(action==='add-mount'){s.sheet.element.querySelector('[data-mounts]').insertAdjacentHTML('beforeend',mountRow());s.sheet.dirty=true;return;}
      if(action==='remove-row'){target.closest('.docker-repeat').remove();s.sheet.dirty=true;return;}
      if(action==='submit-create'||action==='submit-start'){
        if(!s.sheet.element.querySelectorAll('input:invalid').length){const p=createPayload(action==='submit-start');
          if(s.sheet.replacement){const replace=s.sheet.replacement;const changed=Object.keys(p).filter(k=>k!=='confirm'&&JSON.stringify(p[k])!==JSON.stringify(s.sheet.seed[k]));if(await confirm(replace.mode==='clone'?'克隆容器？':'重建容器？',`${p.name} · 变更字段：${changed.join('、')||'重新创建'}。${replace.mode==='clone'?'不会复制卷内数据。':'将保留原容器作为备份；切换期间服务中断。'}`))return await mutate(`/container/${encodeURIComponent(replace.id)}/${replace.mode}`,'POST',{revision:replace.revision,config:p});return;}
          if(await confirm(action==='submit-start'?'创建并启动容器？':'创建容器？',`${p.name||'自动命名'} · ${p.image}。${action==='submit-create'?'创建后保持停止。':'启动后将按所填端口和挂载运行。'}`))return mutate('/container/create','POST',p);}else s.sheet.element.querySelector('input:invalid').reportValidity();return;
      }
      if(action==='clone'||action==='recreate'){const t=await request('/container-template/'+encodeURIComponent(objectId));if(action==='clone')t.config.name=t.config.name+'-copy';return await create(t.config.image,t.config,{id:t.id,revision:t.revision,mode:action});}
      if(action==='detail')return await detail(kind,objectId);
      if(action==='terminal')return await terminal(objectId);
      if(action==='logs'||action==='stats'){
        const data=await request(`/container/${encodeURIComponent(objectId)}/${action}${action==='logs'?'?tail=200&timestamps=true':''}`);
        await sheet(action==='logs'?'最近 200 行日志':'容器监控',action==='logs'?`<pre class="docker-log">${esc(data.logs)}${data.output_truncated?'\n[输出已截断]':''}</pre>`:`<dl class="docker-info"><dt>CPU</dt><dd>${data.sample?.cpu_percent==null?'等待有效采样':esc(data.sample.cpu_percent.toFixed(2))+'%'}</dd><dt>内存 / 上限</dt><dd>${esc(bytes(data.sample?.memory_usage_bytes))} / ${esc(bytes(data.sample?.memory_limit_bytes))}</dd><dt>网络累计接收 / 发送</dt><dd>${esc(bytes(data.sample?.network_rx_bytes))} / ${esc(bytes(data.sample?.network_tx_bytes))}</dd><dt>采样时间</dt><dd>${new Date(data.ts*1000).toLocaleString()}</dd></dl>`,button(action,'刷新','','medium',`data-id="${esc(objectId)}"`));return;
      }
      if(action==='job'){
        const job=await request('/jobs/'+encodeURIComponent(objectId));
        const content=jobMarkup(job);
        await sheet('任务详情',`<div data-job-detail>${content}</div>`,button('job','刷新','','medium',`data-id="${esc(objectId)}"`)+(['container_recreate','network_recreate','network_recover'].includes(job.kind)&&['failed','cancelled'].includes(job.state)&&job.result?.recoverable?button('recover-job',job.kind.startsWith('network_')?'恢复原网络':'恢复原容器',job.kind.startsWith('network_')?'network_recreate':'container_recreate','high',`data-id="${esc(objectId)}" data-kind="${job.kind}"`):''));
        if(s.sheet&&['image_pull','docker_migration'].includes(job.kind)&&['queued','running'].includes(job.state)){s.sheet.pullJob=objectId;s.sheet.jobContent=content;}return;
      }
      if(action==='pull'){await sheet('拉取镜像',field('image','镜像引用','','text','required'),button('submit-pull','拉取','image_pull','high'),true);return;}
      if(action==='submit-pull'){const image=s.sheet.element.querySelector('[name=image]').value;if(image&&await confirm('拉取镜像？',image))return mutate('/image/pull','POST',{image});return;}
      if(action==='new-network'||action==='new-volume'||action==='edit-network'){
        const network=action!=='new-volume',edit=action==='edit-network'?await request(`/network/${encodeURIComponent(objectId)}/edit`):null;
        let options={drivers:['bridge'],parents:[]};
        if(network&&caps().network_ipam)options=await request('/network/options');
        const drivers=options.drivers.filter(x=>x==='bridge'||caps()['network_'+x]);
        const select=(name,label,items)=>`<label class="dwrt-kit-field" data-dwrt-component="field">${label}<select name="${name}" class="dwrt-kit-select">${items}</select></label>`;
        const driverField=select('driver','网络类型',drivers.map(x=>`<option value="${esc(x)}">${x==='ipvlan'?'ipvlan（L2）':esc(x)}</option>`).join(''));
        const parentField=select('parent','父接口','<option value="">选择父接口</option>'+options.parents.map(x=>`<option value="${esc(x.name)}">${esc(x.name)} · ${esc(x.state||'未知')} ${esc((x.addresses||[]).map(a=>a.local+'/'+a.prefixlen).join(', '))}</option>`).join(''));
        await sheet(edit?'编辑网络':network?'创建网络':'创建卷',field('name','名称')+(network&&caps().network_ipam?`${driverField}<div data-network-parent hidden>${parentField}</div>${field('subnet','IPv4 子网（bridge 可留空）','','text','placeholder="例如 10.240.64.0/24"')}${field('gateway','网关')}${field('ip_range','地址池','','text','placeholder="例如 10.240.64.128/25"')}<label class="docker-check" data-network-internal><input type="checkbox" name="internal">仅内部通信</label><p class="docker-muted" data-network-bridge>留空子网时由 Docker 分配。填写后会检查与主机路由和已有 Docker 网络的冲突。</p><div data-network-parent hidden><p class="docker-muted">容器接入所选父接口的二层网络。地址池应使用已预留的静态范围；本机通常不能直接访问这些容器。</p><label class="docker-check"><input type="checkbox" name="acknowledge_dhcp">已确认地址池与局域网 DHCP 范围分开，且没有其他设备使用</label></div>`:''),edit?kit.floatingSavebarMarkup({visible:false,message:'保存将断开端点并重建网络',saveLabel:'预览重建',discardLabel:'撤销修改'}):button(network?'submit-network':'submit-volume',network&&caps().network_ipam?'校验并创建':'创建',network?'network_create':'volume_create'),true);
        if(s.sheet){
          s.sheet.networkCreate=network;
          if(edit){
            s.sheet.kind='network';s.sheet.networkEdit=edit;
            const el=s.sheet.element,c=edit.config;
            const values={name:c.name,driver:c.driver,parent:c.parent||'',subnet:c.ipam.subnet,gateway:c.ipam.gateway||'',ip_range:c.ipam.ip_range||'',internal:!!c.internal,acknowledge_dhcp:false};
            for(const [key,value] of Object.entries(values)){const input=el.querySelector(`[name=${key}]`);if(!input)continue;if(input.type==='checkbox')input.checked=value;else input.value=value;}
            el.querySelector('[name=name]').readOnly=true;el.querySelector('[name=driver]').disabled=true;
            change({target:el.querySelector('[name=driver]')});s.sheet.baseline=values;
          }
        }return;
      }
      if(action==='submit-network'||action==='submit-volume'||action==='submit-network-edit'){
        const edit=s.sheet.networkEdit,k=edit?'network':action.slice(7),get=name=>s.sheet.element.querySelector(`[name=${name}]`)?.value.trim()||'';
        const payload={name:get('name'),driver:k==='network'?(get('driver')||'bridge'):'local'};
        let summary=payload.name;
        if(k==='network'&&caps().network_ipam){
          const subnet=get('subnet'),gateway=get('gateway'),ip_range=get('ip_range');
          if(subnet||gateway||ip_range)payload.ipam={subnet,...(gateway?{gateway}:{}),...(ip_range?{ip_range}:{})};
          const advanced=payload.driver!=='bridge';
          payload.internal=!advanced&&s.sheet.element.querySelector('[name=internal]').checked;
          if(advanced){payload.parent=get('parent');payload.acknowledge_dhcp=s.sheet.element.querySelector('[name=acknowledge_dhcp]').checked;}
          const plan=await request(edit?`/network/${encodeURIComponent(edit.id)}/validate`:'/network/validate','POST',edit?{revision:edit.revision,config:payload}:payload);
          if(advanced&&!payload.acknowledge_dhcp)throw new Error('请先确认地址池已预留，并与局域网 DHCP 范围分开。');
          const checked=edit?{...plan.config,automatic_subnet:false}:plan;
          summary+=checked.automatic_subnet?'，由 Docker 自动分配子网。':`，子网 ${checked.ipam.subnet}${checked.ipam.gateway?'，网关 '+checked.ipam.gateway:''}${checked.ipam.ip_range?'，地址池 '+checked.ipam.ip_range:''}。`;
          if(checked.parent)summary+=`${checked.driver}，父接口 ${checked.parent}。`;
          if(checked.internal)summary+='仅内部通信。';
          if(edit)summary+=`将断开并重新连接 ${(plan.endpoints||[]).map(x=>x.name).join('、')||'0 个端点'}，期间网络连接会中断。静态地址与别名保留，动态地址可能重新分配，容器和数据保留。`;
        }
        if(await confirm(edit?'重建此网络？':'创建'+(k==='network'?'网络':'卷')+'？',summary))return mutate(edit?`/network/${encodeURIComponent(edit.id)}/recreate`:`/${k}/create`,'POST',edit?{revision:edit.revision,config:payload,allow_disconnect:true}:payload);return;
      }
      if(action==='rename'||action==='policy'){await sheet(action==='rename'?'重命名容器':'重启策略',action==='rename'?field('name','新名称'):`<label class="dwrt-kit-field" data-dwrt-component="field">重启策略<select name="restart_policy" class="dwrt-kit-select">${['no','always','unless-stopped','on-failure'].map(x=>`<option>${x}</option>`).join('')}</select></label>`,button('submit-'+action,'保存','container_'+(action==='rename'?'rename':'restart_policy'),'medium',`data-id="${esc(objectId)}"`),true);return;}
      if(action==='submit-rename'||action==='submit-policy'){const rename=action==='submit-rename',key=rename?'name':'restart_policy',value=s.sheet.element.querySelector(`[name=${key}]`).value;if(await confirm('保存修改？',objectId))return mutate(`/container/${encodeURIComponent(objectId)}/${rename?'rename':'restart-policy'}`,'PUT',{[key]:value});return;}
      if(action==='remove'){if(await confirm('删除此对象？',`${objectId}。不会主动删除绑定目录或卷内数据；在用对象由引擎拒绝。`))return mutate(`/${kind}/${encodeURIComponent(objectId)}`,'DELETE');return;}
      if(action==='recover-job'){if(await confirm(kind?.startsWith('network_')?'恢复原网络？':'恢复原容器？',kind?.startsWith('network_')?'将恢复任务记录的网络配置、静态地址和端点别名。网络连接会暂时中断，容器和数据保留。':'将停止这次重建的替代容器，恢复原名称及原运行状态；两个对象和数据均保留。'))return mutate('/jobs/'+encodeURIComponent(objectId)+'/recover','POST');return;}
      if(action==='cancel-job'){if(await confirm('取消任务？','已经产生的容器或下载的镜像层会保留，取消不等于回滚。'))return mutate('/jobs/'+encodeURIComponent(objectId),'DELETE');return;}
      if(action?.startsWith('container-')){const op=action.slice(10);if(await confirm('执行容器操作？',`${objectId}：${target.textContent}。`))return mutate(`/container/${encodeURIComponent(objectId)}/${op}`,'POST');return;}
      if(action?.startsWith('service-')){const op=action.slice(8);if(await confirm('操作 Docker 引擎？','停止、重启或重载可能中断运行中的容器及其网络服务。'))return mutate('/service/'+op,'POST');}
    }catch(error){if(s.sheet)s.sheet.element.querySelector('.docker-sheet-error').textContent=error.message;else root.querySelector('.docker-notice').textContent=error.message;}
  }
  function input(event) {
    if(s.sheet?.element.contains(event.target)) {
      s.sheet.dirty=s.sheet.form;
      if(s.sheet.networkCreate)s.sheet.element.querySelector('.docker-sheet-error').textContent='';
      if(s.sheet.baseline){s.sheet.dirty=Object.entries(s.sheet.baseline).some(([key,value])=>((el)=>el.type==='checkbox'?el.checked:el.value)(s.sheet.element.querySelector(`[name=${key}]`))!==value);s.sheet.element.querySelector('[data-dwrt-savebar]').classList.toggle('is-hidden',!s.sheet.dirty);}
    }
    if(event.target.matches('[data-registry-keyword]'))s.registryKeyword=event.target.value;
    if(root.contains(event.target)&&event.target.matches('[data-docker-search]')){
      s.query=event.target.value;const a=event.target.selectionStart;renderContent();const next=root.querySelector('[data-docker-search]');next.focus();next.setSelectionRange(a,a);
    }
  }
  function change(event){if(s.sheet?.networkCreate&&event.target.name==='driver'){const advanced=event.target.value!=='bridge';s.sheet.element.querySelectorAll('[data-network-parent]').forEach(el=>el.hidden=!advanced);s.sheet.element.querySelectorAll('[data-network-internal],[data-network-bridge]').forEach(el=>el.hidden=advanced);}if(event.target.matches('[data-docker-filter]')&&root.contains(event.target)){s.filter=event.target.value;renderContent();}if(event.target.dataset.dockerSelect){if(event.target.checked)s.selected.add(event.target.dataset.dockerSelect);else s.selected.delete(event.target.dataset.dockerSelect);}}
  const leave=event=>{if(s.sheet?.dirty){event.preventDefault();event.returnValue='';}};
  const escape=event=>{if(event.key==='Escape'){if(s.confirm){event.preventDefault();event.stopImmediatePropagation();s.confirm.finish(false);}else if(s.sheet){event.preventDefault();event.stopImmediatePropagation();if(event.target.closest('[data-container-terminal]'))s.sheet.terminal?.escape();else closeSheet();}}};
  document.addEventListener('click',handle,true);document.addEventListener('input',input);document.addEventListener('change',change);document.addEventListener('keydown',escape,true);window.addEventListener('beforeunload',leave);
  render();refresh();
  const timer=setInterval(()=>{if(visible())refresh();},5000);
  const jobTimer=setInterval(refreshPullJob,1000);
  return {refresh,unmount(){s.alive=false;clearInterval(timer);clearInterval(jobTimer);s.confirm?.finish(false);closeSheet(true);document.removeEventListener('click',handle,true);document.removeEventListener('input',input);document.removeEventListener('change',change);document.removeEventListener('keydown',escape,true);window.removeEventListener('beforeunload',leave);root.replaceChildren();root.className=originalClass;}};
}
