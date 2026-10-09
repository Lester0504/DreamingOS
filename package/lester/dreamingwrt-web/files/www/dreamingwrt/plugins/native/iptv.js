// DreamingWrt IPTV management. Own catalogue, shared Kit/rail, no reference UI code.
const VERSION = '20261007-iptv-input-01';
const A = '/api/v1/iptv/';
const PAGES = [
  ['overview','概览','activity'], ['channels','节目源管理','tv'],
  ['scans','频道扫描','scan-line'], ['categories','节目单管理','list-video'],
  ['viewers','观看用户','users'], ['recordings','回看数据','history'],
  ['inputs','组播接入口','network'], ['settings','系统设置','settings-2']
];
const REASONS = {
  snapshot_not_ready:'截图尚未生成。',snapshot_invalid:'截图输出无效，旧图仍保留。',snapshot_failed:'截图失败，旧图仍保留。',
  encoder_unknown:'编码器不受支持。',encoder_not_compiled:'此 FFmpeg 未编入该编码器。',encoder_smoke_required:'先在系统设置中测试所选编码器。',encoder_smoke_failed:'编码测试失败，硬件或驱动可能不可用；未切换到其他编码器。',encoder_smoke_timeout:'编码测试超时。',encoder_smoke_cancelled:'编码测试已停止。',encoder_smoke_pending:'正在测试编码器。',hevc_requires_fmp4:'H.265 输出需要选择 fMP4 容器。',transcode_budget_exhausted:'转码已达到独立并发上限。',
  recording_requires_managed_ts:'连续录像需要服务器托管的 MPEG-TS 频道。', recording_storage_unavailable:'录像磁盘已离线或挂载已变化。', recording_quota_exceeded:'录像空间已达到配置限额。', recording_not_playable:'录像尚未完成归档与解码验证。', recording_locked:'录像已锁定，请先解锁再删除。', recording_in_use:'录像正在播放，请先关闭播放。', recording_busy:'录像正在写入或归档，请等待结束。', archive_failed:'归档失败，原始 TS 文件已保留。', archive_invalid:'归档文件未通过解码验证。', recording_segment_missing:'录像需要的直播切片已失效。', timeshift_disabled:'当前流未开启时移。请保存频道时移分钟数后重新拉流。', timeshift_window_expired:'所选时间已离开实际保留窗口，请刷新窗口或回到直播。', timeshift_gap:'所选时间没有完整切片，请选择其他区间。',
  igmp_runtime_unavailable:'无法读取所选接收接口的 IGMP 版本。',igmp_version_pending:'配置的 IGMP 版本尚未在接收接口生效。',
  network_runtime_unavailable:'无法读取该接入口的 netifd 运行状态。', input_link_down:'接入口尚未连接。', input_disabled:'接入口已停用。', input_access_mode_not_supported:'该接入模式尚不支持 IPTV 绑定。', input_binding_required:'组播源需要选择现有专用接入口。', input_address_unavailable:'接入口尚未取得 IPv4 地址。', input_is_default_route:'该接口承载默认路由，不能用作专用组播接入口。', network_authority_unavailable:'网络配置服务尚不可用。', scan_template_invalid_or_limit:'地址模板格式错误或展开超过 128 个地址。', scan_budget_invalid:'扫描当前限制为单路，超时范围 2–30 秒。', network_job_busy:'已有列表下载、扫描或截图任务，请等待完成或停止。', playlist_fetch_failed:'播放列表下载失败或超过 512 KiB。',
  iptv_service_unavailable:'IPTV 服务尚未启动，请检查服务安装与运行状态。',
  media_dependency_missing:'设备缺少 FFmpeg 或 ffprobe，托管播放不可用。',
  storage_mount_required:'请选择已挂载的数据磁盘目录。', storage_path_unavailable:'缓存目录不存在或磁盘已离线。',
  storage_space_insufficient:'缓存磁盘可用空间不足。', storage_not_writable:'缓存目录不可写。',
  required:'请填写名称。',invalid_vlan:'VLAN ID 必须为 1–4094。',invalid_mtu:'MTU 必须为 576–1500。',pppoe_credentials_required:'请填写 PPPoE 账号与密码。',one_address_required:'静态接入需要一个 IPv4 地址。',invalid_address:'请检查 IPv4 地址和前缀长度（1–30）。',subnet_in_use:'地址网段与已有网络重叠。',input_policy_in_use:'该接口被 DNS 或混合线路策略引用，请先处理引用。',carrier_missing:'设备上未找到所选物理端口。',carrier_enslaved:'端口已加入桥或聚合接口。',carrier_has_address:'端口已有 IPv4 地址，请先核对所属网络。',uci_resource_in_use:'接口或端口已被其他网络配置引用。',input_has_default_route:'接入口已有默认路由，不能作为专用 IPTV 接入口。',
  carrier_in_use:'端口已被其他网络资源占用，请选择独立端口。',physical_port_required:'请选择实际的以太网物理端口。',port_profile_in_use:'端口已有 VLAN 配置，不能分配为专用接入口。',multicast_service_in_use:'此端口已被组播服务使用，请先核对所属资源。',input_not_owned:'该接口不属于 IPTV 专用接入口。',input_in_use:'仍有频道引用此接入口，请先更换频道绑定。',management_path_in_use:'此端口承载当前管理连接，不能用于此次更改。',management_route_unavailable:'无法确认当前管理连接的返回路径，未应用更改。',stale_watchdog_digest_mismatch:'应用后有其他网络配置变化，自动恢复已停止，请核对实际网络状态。',transaction_pending:'已有网络事务等待确认，请先处理。',
  revision_conflict:'配置已被另一处修改。草稿已保留，请刷新版本后核对。',
  module_disabled:'IPTV 服务已在系统设置中关闭。', media_budget_exhausted:'媒体任务已达到资源上限，请先停止不用的预览或探测。',
  first_segment_pending:'正在等待首片', first_segment_timeout:'等待首片超时。请检查源地址和媒体编码。',
  media_process_exited:'媒体进程已退出。请重新探测源并检查设备诊断。', stream_stalled:'媒体切片已停止更新。',
  media_session_expired:'预览授权已失效，请重新打开预览。', channel_unavailable:'频道或其分类已停用，无法继续播放。',
  source_secret_store_unavailable:'设备秘密存储尚不可用，访问凭据未保存。',source_access_address_mismatch:'访问地址去除账号和查询参数后，必须与节目源地址一致。',source_access_conflict:'替换访问地址和清除访问凭据不能同时执行。',source_access_export_unsupported:'频道表含访问凭据，当前不支持此类 XLSX 迁移。',source_access_protocol_unsupported:'访问凭据仅支持 HTTP(S)、RTSP 和 RTMP。',category_in_use:'分类仍有频道，请先移动频道。', source_credentials_not_supported:'节目源地址只填公开部分；账号和查询参数请填入完整访问地址。',
  input_protocol_unsupported:'源协议不受支持。', source_timeout:'源探测超时。', video_stream_not_found:'源中未探测到视频流。',
  epg_source_in_use:'该节目源仍被频道引用，请先解除映射。', epg_mapping_required:'请先编辑频道并选择节目源与节目 ID。', epg_source_not_found:'所选节目源不存在，请重新选择。', input_protocol_not_compiled:'本机 FFmpeg / ffprobe 未编译此输入协议。',media_capabilities_unavailable:'无法读取本机媒体工具能力。',hls_output_not_compiled:'本机 FFmpeg 未编译 HLS 输出。',source_probe_required:'此协议或容器播放前需要先探测本次频道配置。', watching_not_permitted:'观看授权已停用、到期或不包含此频道。', media_identity_unavailable:'观看身份不可用，请检查会话、媒体主体与 TV 模块设置。', storage_unavailable_or_budget_exceeded:'媒体磁盘已不可用或达到缓存限额。', source_probe_failed:'源探测失败。', channel_busy:'此频道正在运行，请先结束当前任务。', requires_confirmation:'请确认此操作对正在观看的用户的影响。'
};
export function mount(context={}) {
  const root=context.root, ui=context.ui||window.DWRT_UI_KIT||{}, api=context.api||{};
  if(!root)return {unmount(){}};
  const esc=context.utils?.escapeHtml||((v)=>String(v??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])));
  const s={page:'overview',data:null,error:'',notice:'',draft:null,baseline:null,kind:'',id:'',baseRevision:0,busy:false,confirmation:null,query:'',alive:true,player:null,hls:null,sequence:0,tab:'arrangement',principals:[],importer:null,importPreview:null,order:null,epgGuide:null,inputs:[],inputsLoaded:false,inputsError:'',scans:[],scanDraft:{template:'',input_id:'',timeout_seconds:10},scanPlan:null,scanId:'',scanEdits:{},scanImport:null,conflict:false,recordings:{items:[],captures:[],used_bytes:0},cleanup:null,recordFilter:'',selected:{channels:[],viewers:[]},batchResult:null,sessions:[],bulkGrant:false,storageCheck:null,draftProbe:null,recordDate:'',recordSearch:'',inputContext:null,inputPlan:null,inputSupport:null,networkTask:null};
  let poll=null,renew=null,playerTimer=null;
  const clone=v=>JSON.parse(JSON.stringify(v));
  try{s.networkTask=JSON.parse(sessionStorage.getItem('iptv.network-task')||'null');}catch{}
  const networkPending=()=>s.networkTask&&['pending','rolling_back','unknown'].includes(s.networkTask.state);
  if(networkPending())s.page='inputs';
  const rememberNetwork=()=>{try{const t=s.networkTask;sessionStorage.setItem('iptv.network-task',JSON.stringify(t?{key:t.key,task_id:t.task_id,input_id:t.input_id,state:t.state}:null));}catch{}};
  const dirty=()=>!!s.order||!!(s.draft&&JSON.stringify(s.draft)!==JSON.stringify(s.baseline));
  const unsaved=()=>dirty()||!!(s.importer?.text||s.importer?.base64)||networkPending();
  const collection=kind=>kind==='channels'?channels():kind==='categories'?categories():kind==='epg-sources'?(s.data?.epg_sources?.items||[]):(s.data?.viewers?.items||[]);
  const date=t=>t?new Date(t*1000).toLocaleString():'—';
  const desktop=new URLSearchParams(location.search).get('desktop')==='1';
  const controller=new AbortController();
  const canWrite=()=>s.data?.can_manage===true;
  const caps=()=>s.data?.capabilities||{};
  const channels=()=>s.data?.channels?.items||[];
  const categories=()=>s.data?.categories?.items||[];
  const icon=(name)=>ui.lucideIcon?.(name,{size:18})||window.DWRT_UI_KIT?.lucideIcon?.(name,{size:18})||'';
  const button=(label,action,disabled=false,id='')=>`<button class="dwrt-kit-button" data-dwrt-component="button" type="button" data-action="${action}" data-id="${esc(id)}" ${disabled?'disabled':''}>${esc(label)}</button>`;
  async function req(resource,method='GET',body) {
    const path=resource.startsWith('/api/')?resource:A+resource;
    try {
      if(api.request)return await api.request('IPTV',path,{method,signal:controller.signal,...(body!==undefined?{body}: {})});
      const response=await (window.DWRT_REQUEST?.fetch.bind(window.DWRT_REQUEST)||fetch)(path,{method,credentials:'same-origin',signal:controller.signal,headers:{...api.authHeaders?.(),...(body!==undefined?{'Content-Type':'application/json'}:{})},...(body!==undefined?{body:JSON.stringify(body)}:{})});
      const payload=await response.json();
      if(!response.ok||payload.ok===false)throw Object.assign(new Error(payload.error?.code||payload.error||String(response.status)),{status:response.status,payload});
      return payload.data??payload;
    }catch(error){
      const code=error.payload?.error?.code||error.payload?.error||error.message;
      error.code=code;error.message=(code==='validation_failed'&&error.payload?.errors?.length?error.payload.errors.map(e=>(REASONS[e.reason]||e.message)).join('；'):'')||REASONS[code]||(error.status===401?'管理会话已过期。':error.status===403?'当前账户没有此操作权限。':[404,405,501].includes(error.status)?'当前固件尚未提供此接口。':error.message||'无法连接 IPTV 服务。');throw error;
    }
  }
  function field(key,label,type='text',options=null) {
    const value=s.draft?.[key]??'';
    if(type==='categories')return `<fieldset class="iptv-field"><legend>${esc(label)}</legend>${[['','未分类'],...categories().map(c=>[c.id,c.name])].map(([id,name])=>`<label><input type="checkbox" data-grant-category="${esc(id)}" ${(value||[]).includes(id)?'checked':''} ${!canWrite()||s.busy||(s.kind==='inputs'&&networkPending())?'disabled':''}> ${esc(name)}</label>`).join('')}</fieldset>`;
    return `<label class="dwrt-kit-field iptv-field" data-dwrt-component="field"><span>${esc(label)}</span>${options?`<select class="dwrt-kit-input" data-field="${key}" ${!canWrite()||s.busy||(s.kind==='inputs'&&networkPending())?'disabled':''}>${options.map(([id,text,disabled])=>`<option value="${esc(id)}" ${disabled?'disabled':''} ${String(value)===String(id)?'selected':''}>${esc(text)}</option>`).join('')}</select>`:type==='checkbox'?`<input type="checkbox" data-field="${key}" ${value?'checked':''} ${!canWrite()||s.busy||(s.kind==='inputs'&&networkPending())?'disabled':''}>`:`<input class="dwrt-kit-input" type="${type}" data-field="${key}" value="${esc(value)}" ${!canWrite()||s.busy||(s.kind==='inputs'&&networkPending())?'disabled':''}>`}</label>`;
  }
  function savebar() {
    const f=ui.floatingSavebarMarkup||window.DWRT_UI_KIT?.floatingSavebarMarkup;
    // Kit supplies the material and actions; this window owns placement.
    return dirty()&&f?f({visible:true,omitWhenHidden:true,busy:s.busy,disabled:!canWrite()||s.busy||(s.kind==='inputs'&&networkPending()),message:'有未保存的更改',saveLabel:s.kind==='inputs'?'预检':'保存',discardLabel:'撤销',busyLabel:'正在保存'}).replace('dwrt-floating-savebar ',''):'';
  }
  function syncSavebar(){const holder=root.querySelector('[data-savebar]');if(holder)holder.innerHTML=savebar();ui.mountAll?.(holder);}
  function blank(title,text){return `<div class="iptv-empty"><strong>${esc(title)}</strong><p>${esc(text)}</p></div>`;}
  const stateLabel = r=>({stopped:'已停止',starting:'等待首片',media_ready:'切片就绪',probing:'探测中',probe_complete:'探测完成',retrying:'等待重连',error:'运行错误'}[r?.state]||'状态未确认');
  function table(head,rows){return `<section class="dwrt-kit-table-wrap"><div class="dwrt-kit-table-scroll"><table class="dwrt-kit-table"><thead><tr>${head.map(h=>`<th>${esc(h)}</th>`).join('')}</tr></thead><tbody>${rows.join('')}</tbody></table></div></section>`;}
  const names={channels:'频道',categories:'分类','epg-sources':'节目源',viewers:'观看授权'};
  const selected=(kind,id)=>`<input type="checkbox" data-select-kind="${kind}" data-select-id="${esc(id)}" ${(s.selected[kind]||[]).includes(id)?'checked':''} ${!canWrite()||s.busy||(s.kind==='inputs'&&networkPending())?'disabled':''} aria-label="选择${esc(collection(kind).find(r=>r.id===id)?.name||id)}">`;
  function batchToolbar(kind){return `${button('启用选中','batch-enable',!canWrite()||!s.selected[kind].length,kind)}${button('停用选中','batch-disable',!canWrite()||!s.selected[kind].length,kind)}${button('删除选中','batch-delete',!canWrite()||!s.selected[kind].length,kind)}`;}
  function batchResults(){return s.batchResult?table(['条目','结果'],s.batchResult.items.map(r=>`<tr><td>${esc(r.id||String(r.index+1))}</td><td>${r.saved?'已保存':esc(REASONS[r.error]||r.error)}</td></tr>`)):'';}
  function snapshotPanel(){
    if(!s.snapshot)return '';
    const shot=s.snapshot,attempt=shot.last_attempt;
    return `<section class="iptv-editor"><header><strong>频道截图 · ${esc(channels().find(c=>c.id===shot.id)?.name||'')}</strong>${button('关闭截图','snapshot-close')}</header><p>${attempt?esc(jobState(attempt)):''}${attempt?.error?' · '+esc(REASONS[attempt.error]||attempt.error):''}</p>${shot.base64?`<img class="iptv-snapshot-image" src="data:image/jpeg;base64,${shot.base64}" alt="${esc(channels().find(c=>c.id===shot.id)?.name||'频道')}在${date(shot.captured_at)}的截图"><p>拍摄时间：${date(shot.captured_at)}</p>`:`<p>${shot.state==='unavailable'?'旧截图所在磁盘不可用。':'尚无可用截图。'}</p>`}${button('重新截图','snapshot',!canWrite()||['queued','running'].includes(attempt?.state),shot.id)}</section>`;
  }
  function encoderChoices(type){
    const choices=[['copy','保留源编码（copy）'],...(caps().encoders||[]).filter(c=>c.type===type&&c.runtime_available).map(c=>[c.id,c.codec.toUpperCase()+' · '+c.id])];
    const current=s.draft?.[type+'_encoder'];
    if(current&&!choices.some(c=>c[0]===current))choices.push([current,current+' · 需重新测试',true]);
    return choices;
  }
  function encoderPanel(){
    return `<h2>编码器</h2><p class="iptv-help">测试使用一秒合成媒体，占用一个媒体任务名额。通过后才能选择；服务重启后需重新测试。硬件失败不会自动改用软件。</p>${table(['编码器','状态','测试'],(caps().encoders||[]).map(c=>`<tr><td>${esc(c.id)}<small>${c.hardware==='software'?'软件':esc(c.hardware)}</small></td><td>${c.runtime_available?'已通过实际编码':esc(REASONS[c.reason]||c.reason)}<small>${date(c.probed_at)}</small></td><td>${button('测试编码','encoder-probe',!canWrite()||!c.compiled||c.state==='testing',c.id)}${c.state==='testing'?button('停止测试','encoder-stop',!canWrite(),c.id):''}</td></tr>`))}`;
  }
  const inputSnapshot=id=>req('/api/v1/config/snapshot?domain=iptv&id='+encodeURIComponent(id));
  function inputDraft(config){
    const keys=['name','note','device','access_mode','enabled','vlan_enabled','vlan_id','mtu','gateway','username','option60'];
    keys.push(...['igmp_version','multicast_source','carrier_access_mode','carrier_address','carrier_prefix'].filter(k=>Object.prototype.hasOwnProperty.call(config,k)));
    return {...Object.fromEntries(keys.map(k=>[k,config[k]??''])),password:'',clear_password:false,
      static_ip:config.addresses?.[0]?.ip||'',prefix:config.addresses?.[0]?.prefix||24};
  }
  async function editInput(id=''){
    if(networkPending())throw new Error('请先处理当前网络事务。');
    let snapshot;
    if(id)snapshot=await inputSnapshot(id);
    else for(let n=0;n<8;n++){
      const value=crypto.getRandomValues(new Uint16Array(1))[0].toString(16).padStart(4,'0');
      snapshot=await inputSnapshot('iptv_'+value);if(!snapshot.config?.exists)break;
    }
    if(!snapshot?.write_supported||(!id&&snapshot.config?.exists))throw new Error('当前接入口不可写，请刷新网络资源后重试。');
    s.kind='inputs';s.id=snapshot.id;s.inputContext=snapshot;s.baseRevision=snapshot.revision;
    s.draft=inputDraft(snapshot.config);s.baseline=clone(s.draft);s.inputPlan=null;s.conflict=false;s.error='';render();
  }
  function inputEditor(){
    const config=s.inputContext?.config||{},d=s.draft;
    const choices=(s.inputContext?.ports||[]).filter(p=>p.kind==='ethernet').map(p=>[p.name,(p.label||p.name)+(p.owner_id&&p.owner_id!==s.id?' · 已被 '+p.owner_id+' 占用':'')]);
    let fields=field('name','名称')+field('enabled','启用接入口','checkbox')+field('device','专用物理端口','text',[['','请选择'],...choices])+field('access_mode','接入方式','text',[['dhcp','DHCP'],['static','静态 IPv4'],['pppoe','PPPoE']])+field('vlan_enabled','使用 VLAN','checkbox');
    if(d.vlan_enabled)fields+=field('vlan_id','VLAN ID（1–4094）');
    if(Object.prototype.hasOwnProperty.call(config,'igmp_version'))fields+=field('igmp_version','IGMP 版本','text',[[0,'系统默认'],[2,'IGMPv2'],[3,'IGMPv3']]);
    if(d.access_mode==='pppoe'&&Object.prototype.hasOwnProperty.call(config,'multicast_source')){
      fields+=field('multicast_source','组播接收接口','text',[['session','PPPoE 会话接口'],['carrier','独立物理 / VLAN 承载接口']]);
      if(d.multicast_source==='carrier'){
        fields+=field('carrier_access_mode','承载接口地址方式','text',[['dhcp','DHCP'],['static','静态 IPv4']]);
        if(d.carrier_access_mode==='static')fields+=field('carrier_address','承载 IPv4 地址')+field('carrier_prefix','承载前缀长度（1–30）','number');
      }
    }
    if(d.access_mode==='dhcp'||(d.access_mode==='pppoe'&&d.multicast_source==='carrier'&&d.carrier_access_mode==='dhcp'))fields+=field('option60','DHCP Option 60（可选）');
    if(d.access_mode==='static')fields+=field('static_ip','IPv4 地址')+field('prefix','前缀长度（1–30）','number')+field('gateway','网关（可选，不设默认路由）');
    if(d.access_mode==='pppoe')fields+=field('username','PPPoE 账号')+field('password',config.password_set?'PPPoE 密码（留空保留）':'PPPoE 密码','password');
    fields+=field('mtu','MTU（576–1500）','number')+field('note','备注');
    const plan=s.inputPlan;
    return `<section class="iptv-editor"><header><strong>${config.exists?'编辑':'新建'}专用接入口</strong>${button('关闭','close-editor',s.busy)}</header><div class="iptv-fields">${fields}</div><p class="iptv-help">端口必须独立且未分配给桥、其他 WAN 或组播代理。PPPoE 的独立承载接口用于接收物理 / VLAN 侧组播，不使用 PPP 会话地址。配置应用与取得地址、收到频道媒体分别验证。</p>${plan?`<section aria-label="网络变更预检"><h3>预检通过</h3><p>${esc(({create:'新建',update:'修改',delete:'删除',reconnect:'重连'})[plan.body.operation])} ${esc(d.name)} · ${esc(d.device)}${d.vlan_enabled?' · VLAN '+esc(d.vlan_id):''}</p><p>默认路由与 DNS 保持；影响 ${plan.result.channel_references?.length||0} 个引用频道。${plan.result.interrupts_input?'该接入口会短暂中断。':''}</p>${button('应用网络更改','input-apply',s.busy||networkPending())}</section>`:''}</section>`;
  }
  async function inputPreflight(operation=''){
    if(!s.draft||networkPending())return;
    const d=clone(s.draft),{static_ip,prefix,...config}=d;
    config.addresses=d.access_mode==='static'?[{ip:static_ip,prefix,primary:true}]:[];
    if('igmp_version' in config)config.igmp_version=Number(config.igmp_version);
    if('multicast_source' in config&&d.access_mode!=='pppoe')config.multicast_source='session';
    if(d.access_mode!=='dhcp'&&!(d.access_mode==='pppoe'&&d.multicast_source==='carrier'&&d.carrier_access_mode==='dhcp'))config.option60='';
    if(d.access_mode!=='static')config.gateway='';
    operation=operation||(s.inputContext.config.exists?'update':'create');
    const body={domain:'iptv',id:s.id,operation,if_revision:s.baseRevision,...(['create','update'].includes(operation)?{config}:{})};
    s.busy=true;s.error='';s.inputPlan=null;syncSavebar();
    try{const result=await req('/api/v1/config/validate','POST',body);if(!result.valid)throw new Error(result.error||'网络预检未通过。');s.inputPlan={body,result};}
    catch(e){s.error=e.message;s.conflict=e.code==='revision_conflict';}
    finally{s.busy=false;render();}
  }
  async function readNetworkTask(){
    if(!s.networkTask?.key)return;
    const previous=s.networkTask;
    try{
      const result=await req('/api/v1/config/last-apply?idempotency_key='+encodeURIComponent(previous.key));
      if(result.found===false){s.networkTask={...previous,state:'unknown',error:'尚未查到此次操作结果。请稍后读取，勿重复应用。'};return;}
      const task=result.task||result;
      s.networkTask={...task,task_id:task.task_id||task.id,key:previous.key,input_id:previous.input_id};
      if(task.state==='confirmed'&&s.kind==='inputs'&&s.id===previous.input_id){s.draft=null;s.baseline=null;s.inputPlan=null;s.notice='接入口配置已保留。';}
      try{s.networkTask.current=await inputSnapshot(previous.input_id);}catch{ s.networkTask.current=null; }
      rememberNetwork();
    }catch(e){s.networkTask={...previous,error:e.message};}
  }
  async function applyInput(plan){
    if(networkPending()||plan!==s.inputPlan)return;
    s.busy=true;s.networkTask={key:'iptv-'+crypto.randomUUID(),input_id:plan.body.id,state:'unknown'};rememberNetwork();render();
    try{
      const result=await req('/api/v1/config/apply','POST',{...plan.body,confirm_risk:true,rollback_timeout:90,idempotency_key:s.networkTask.key});
      const task=result.task||result;s.networkTask={...task,task_id:task.task_id||task.id,key:s.networkTask.key,input_id:plan.body.id};
      rememberNetwork();s.inputPlan=null;await readNetworkTask();await load();
    }catch(e){
      s.error=e.message;
      if(e.status>=400&&e.status<500&&e.code!=='transaction_pending'){s.networkTask=null;rememberNetwork();s.conflict=e.code==='revision_conflict';}
      else {await readNetworkTask();rememberNetwork();}
    }finally{s.busy=false;render();}
  }
  function inputTaskPanel(){
    const t=s.networkTask;if(!t)return '';
    const labels={pending:'网络配置已应用，等待保留确认',confirmed:'网络配置已保留',rolling_back:'正在恢复原配置',rolled_back:'已恢复原配置',rollback_failed:'恢复失败，需检查网络状态',unknown:'操作结果尚未确认'};
    const readback=t.readback?.find(r=>r.domain==='iptv'),runtime=t.current?.runtime||readback?.runtime;
    const ip=runtime?.['ipv4-address']?.map(a=>a.address).join(' · ');
    return `<section class="iptv-editor" aria-label="接入口网络事务"><header><strong>${esc(labels[t.state]||t.state||'事务状态未知')}</strong></header><p>${esc(t.input_id||'')}${t.state==='pending'?` · 剩余 ${Number.isFinite(t.seconds_left)?t.seconds_left:'—'} 秒，未保留将自动回滚`:''}</p>${readback?`<p>${t.current?'当前运行回读':'应用时回读'}；接口 ${esc(runtime?.l3_device||'尚未就绪')} · IPv4 ${esc(ip||'尚未取得')}。频道接收情况需主动探测。</p>`:''}${t.error?`<p role="alert">${esc(REASONS[t.error]||t.error)}</p>`:''}<div class="iptv-actions">${button('读取事务状态','input-task-refresh',s.busy)}${t.state==='pending'?button('保留更改','input-confirm',!canWrite()||s.busy||!(t.seconds_left>0)||readback?.applied!==true)+button('回滚','input-rollback',!canWrite()||s.busy):''}</div></section>`;
  }
  function editor(){
    if(!s.draft||s.kind==='settings')return '';
    if(s.kind==='inputs')return inputEditor();
    let fields=(s.bulkGrant?'':field('name','名称'))+field('enabled','启用','checkbox')+field('position','排序','number');
    if(s.kind==='channels')fields+=field('number','频道号','number')+field('category_id','分类','text',[['','未分类'],...categories().map(c=>[c.id,c.name])])+field('mode','播放方式','text',[['managed','服务器托管'],['external','客户端直连']])+field('source_url','节目源地址','url')+field('input_id','组播接入口','text',[['','无需绑定（HTTP / RTSP / RTMP）'],...s.inputs.map(i=>[i.id,i.name+(i.available?'':' · 当前不可用')])])+field('hls_container','HLS 容器','text',(caps().hls_containers||['mpegts']).map(c=>[c,c==='fmp4'?'fMP4（先探测）':'MPEG-TS']))+field('video_encoder','视频输出','text',encoderChoices('video'))+field('audio_encoder','音频输出','text',encoderChoices('audio'))+field('video_bitrate_kbps','转码视频码率（Kbps）','number')+field('audio_bitrate_kbps','转码音频码率（Kbps）','number')+field('program_id','源内节目号（0 使用首个节目）','number')+field('rtsp_transport','RTSP 传输','text',[['','默认 TCP'],['tcp','TCP'],['udp','UDP']])+field('user_agent','HTTP User-Agent（可选）')+field('timeshift_minutes','时移保留上限（分钟，0 关闭）','number')+field('epg_source_id','节目预告来源','text',[['','不关联'],...collection('epg-sources').map(c=>[c.id,c.name])])+field('epg_id','XMLTV 频道 ID')+field('logo_url','台标地址','url');
    if(s.kind==='channels'&&(caps().source_credentials||channels().find(c=>c.id===s.id)?.has_access_url))fields+=field('access_url','完整访问地址（含账号或查询参数；留空保留）','password')+field('clear_access_url','清除已保存的访问凭据','checkbox');
    if(s.kind==='epg-sources')fields+=field('url','XMLTV / XMLTV.gz 地址','url')+field('interval_hours','更新间隔（小时）','number');
    if(s.kind==='viewers')fields+=(s.bulkGrant?`<fieldset class="iptv-field"><legend>选择已有媒体主体</legend>${s.principals.filter(p=>p.enabled&&!collection('viewers').some(v=>v.principal_id===p.id)).map(p=>`<label><input type="checkbox" data-bulk-principal="${esc(p.id)}" ${(s.draft.principal_ids||[]).includes(p.id)?'checked':''}> ${esc(p.name)}</label>`).join('')||'<p>所有可用主体均已开通，或当前没有可用主体。</p>'}</fieldset>`:field('principal_id','已有媒体主体','text',[['','请选择'],...s.principals.filter(p=>p.enabled).map(p=>[p.id,p.name])]))+field('all_categories','授权全部分类','checkbox')+field('category_ids','授权分类','categories')+field('expires_at','到期时间（Unix 秒；0 为不过期）','number');
    return `<section class="iptv-editor" data-dwrt-surface="stable-glass"><header><strong>${s.id?'编辑':'新建'}${names[s.kind]}</strong>${button('关闭','close-editor')}</header><div class="iptv-fields">${fields}</div>${s.kind==='channels'?`<p class="iptv-help">${s.draft.mode==='external'?'客户端直接访问原源；本机不转码、录制或统计持续观看。':'copy 保留源编码；转码按所选编码器执行。切片就绪后还需要播放器实际解码。'}</p><div class="iptv-toolbar">${button('探测草稿','draft-probe',!canWrite()||!caps().draft_probe||s.draft.mode==='external')}${button('读取探测结果','draft-probe-result',!s.draftProbe)}${button('停止探测','draft-probe-stop',!s.draftProbe)}</div><p data-draft-probe-status>${s.draftProbe?esc(stateLabel(s.draftProbe)):'探测不会保存频道；已保存凭据请使用频道行的探测，替换凭据可直接探测当前草稿。'}</p>`:''}</section>`;
  }
  function importer(){
    if(!s.importer)return '';
    return `<section class="iptv-editor" data-dwrt-surface="stable-glass"><header><strong>导入频道数据</strong>${button('关闭','close-import')}</header><p class="iptv-help">${s.importer.format==='xlsx'?'系统表格按每行播放方式迁移；未支持字段明确报错。':'播放列表创建客户端直连频道。'}预览不会保存或启动拉流。</p><div class="iptv-toolbar"><label>格式 <select class="dwrt-kit-input" data-import-field="format"><option value="m3u" ${s.importer.format==='m3u'?'selected':''}>M3U</option><option value="txt" ${s.importer.format==='txt'?'selected':''}>TXT</option><option value="xlsx" ${s.importer.format==='xlsx'?'selected':''}>XLSX 系统频道表</option></select></label><label>重复源 <select class="dwrt-kit-input" data-import-field="duplicates"><option value="skip" ${s.importer.duplicates==='skip'?'selected':''}>跳过</option><option value="update" ${s.importer.duplicates==='update'?'selected':''}>更新</option></select></label>${s.importer.format!=='xlsx'?`<label>一次性列表 URL <input class="dwrt-kit-input" data-import-field="url" type="url" value="${esc(s.importer.url||'')}"></label>${button('下载并预览','import-fetch',!canWrite()||s.busy||!caps().url_import)}<span>${s.importer.fetchState?esc(({queued:'等待下载',running:'下载中',complete:'下载完成',failed:'下载失败',cancelled:'已取消'})[s.importer.fetchState]||s.importer.fetchState):''}</span>`:''}<label>选择文件 <input type="file" accept=".m3u,.m3u8,.txt,.xlsx" data-import-file></label></div>${s.importer.format==='xlsx'?`<p>${esc(s.importer.filename||'请选择 XLSX 文件')}</p>`:`<label class="iptv-field">播放列表文本<textarea class="dwrt-kit-input" data-import-field="text" rows="7">${esc(s.importer.text)}</textarea></label>`}<div class="iptv-toolbar">${button('预览导入','import-preview',!canWrite()||s.busy)}${button('确认导入','import-commit',!canWrite()||s.busy||!s.importPreview||s.importPreview.persisted)}</div>${s.importPreview?table(['行','频道','结果'],s.importPreview.rows.map(r=>`<tr><td>${r.line}</td><td>${esc(r.name)}</td><td>${esc(({create:'新增',update:'更新',skip:'跳过',error:'错误'})[r.action])}${r.error?`<small>${esc(REASONS[r.error]||r.error)}</small>`:''}</td></tr>`)):''}</section>`;
  }
  function programme(){
    const tabs=`<div class="iptv-toolbar" role="tablist">${[['arrangement','频道编排'],['guide','节目预告']].map(([id,label])=>`<button class="dwrt-kit-button" type="button" role="tab" aria-selected="${s.tab===id}" data-guide-tab="${id}">${label}</button>`).join('')}</div>`;
    if(s.tab==='guide'){
      const sources=collection('epg-sources');
      return tabs+`<div class="iptv-toolbar">${button('新增节目源','new-epg',!canWrite()||!caps().epg)}</div>${editor()}${sources.length?table(['节目源','最近更新','操作'],sources.map(c=>{const j=s.data?.epg_jobs?.items?.find(j=>j.source_id===c.id);return `<tr><td>${esc(c.name)}<small>${c.enabled?'启用':'停用'}</small></td><td>${date(j?.last_success)}<small>${esc(({queued:'等待更新',running:'更新中',complete:'更新完成',failed:'更新失败',interrupted:'更新中断'})[j?.state]||'尚未更新')}${j?.error?' · '+esc(REASONS[j.error]||j.error):''}</small></td><td>${button('编辑','edit-epg',!canWrite(),c.id)}${button('更新','refresh-epg',!canWrite()||!c.enabled,c.id)}${button('删除','delete-epg',!canWrite(),c.id)}</td></tr>`;})):blank('暂无节目源','添加 XMLTV 来源并在频道编辑器中确认映射。')}<div class="iptv-toolbar"><select class="dwrt-kit-input" data-guide-channel aria-label="选择节目预告频道"><option value="">选择频道</option>${channels().map(c=>`<option value="${esc(c.id)}" ${s.epgGuide?.channel===c.id?'selected':''}>${esc(c.name)}</option>`).join('')}</select>${button('查询节目','guide-load')}</div>${s.epgGuide?table(['开始','结束','节目 / 已有录像'],s.epgGuide.items.map(p=>`<tr><td>${date(p.start)}</td><td>${date(p.end)}</td><td>${esc(p.title)}${p.recordings?.length?p.recordings.map(r=>`<button class="dwrt-kit-button" data-action="guide-recording" data-id="${esc(r.recording_id)}" data-offset="${r.offset_seconds}">回看 ${date(r.start)} — ${date(r.end)}</button>`).join(''):'<small>当前没有可播放录像</small>'}</td></tr>`)):''}`;
    }
    const ids=s.order?.kind==='channels'?s.order.ids:channels().map(c=>c.id);
    const groups=s.order?.kind==='categories'?s.order.ids.map(id=>categories().find(c=>c.id===id)):categories();
    return tabs+`<div class="iptv-toolbar">${button('新建分类','new-category',!canWrite())}${button('导入频道','open-import',!canWrite()||!caps().m3u_import)}${button('XLSX 模板','xlsx-template',!caps().xlsx_import)}${button('导出 XLSX','xlsx-export',!canWrite()||!caps().xlsx_import)}${button('导出直连 M3U','export-m3u',!canWrite())}</div>${importer()}${editor()}${categories().length?table(['分类','排序','状态','操作'],groups.map((c,i)=>`<tr><td>${esc(c.name)}</td><td>${button('上移','category-up',!canWrite()||i===0,c.id)}${button('下移','category-down',!canWrite()||i===groups.length-1,c.id)}</td><td>${c.enabled?'启用':'停用'}</td><td>${button('编辑','edit-category',!canWrite(),c.id)}${button('删除','delete-category',!canWrite(),c.id)}</td></tr>`)):blank('暂无分类','未分类频道仍显示在频道目录中。')}${ids.length?table(['频道编排','分类','顺序'],ids.map((id,i)=>{const c=channels().find(c=>c.id===id);return `<tr><td>${esc(c.name)}</td><td>${esc(categories().find(k=>k.id===c.category_id)?.name||'未分类')}</td><td>${button('上移','order-up',!canWrite()||i===0,id)}${button('下移','order-down',!canWrite()||i===ids.length-1,id)}</td></tr>`;})):''}<p class="iptv-help">URL 只下载本次列表，导入前还需确认；不会自动订阅。排序修改在保存后一次提交。</p>`;
  }
  const jobState=j=>({queued:'等待执行',running:'执行中',complete:'已完成',failed:'失败',cancelled:'已停止',interrupted:'服务重启中断'})[j?.state]||'—';
  function scansPage(){
    const current=s.scans.find(j=>j.id===s.scanId),rows=current?.result?.rows||[];
    return `<section class="iptv-editor" data-dwrt-surface="stable-glass"><div class="iptv-fields"><label class="iptv-field">地址模板<input class="dwrt-kit-input" data-scan-field="template" value="${esc(s.scanDraft.template)}" placeholder="http://host/channel/[1-4].ts"></label><label class="iptv-field">组播接入口<select class="dwrt-kit-input" data-scan-field="input_id"><option value="">无需绑定</option>${s.inputs.map(i=>`<option value="${esc(i.id)}" ${i.id===s.scanDraft.input_id?'selected':''}>${esc(i.name)}</option>`).join('')}</select></label><label class="iptv-field">单地址超时（秒）<input class="dwrt-kit-input" type="number" min="2" max="30" data-scan-field="timeout_seconds" value="${s.scanDraft.timeout_seconds}"></label></div><p class="iptv-help">只探测你有权使用的范围。数字范围写为 [1-4]，最多 128 个地址，单路串行并占用媒体预算。离开页面后已启动任务继续。</p><div class="iptv-toolbar">${button('预览范围','scan-preview',!canWrite()||s.busy)}${button('开始扫描','scan-start',!canWrite()||!s.scanPlan||s.busy)}</div>${s.scanPlan?`<p>共 ${s.scanPlan.count} 个地址 · 并发 1</p><details><summary>查看展开地址</summary><pre class="iptv-addresses">${esc(s.scanPlan.urls.join('\n'))}</pre></details>`:''}</section>${s.scans.length?table(['扫描任务','状态','操作'],s.scans.map(j=>`<tr><td>${esc(j.payload.template)}<small>${date(j.created_at)}</small></td><td>${jobState(j)} · ${j.result.completed||0}/${j.payload.count}</td><td>${button('结果','scan-open',false,j.id)}${button('停止','scan-stop',!canWrite()||!['queued','running'].includes(j.state),j.id)}${button('删除记录','scan-delete',!canWrite()||['queued','running'].includes(j.state),j.id)}</td></tr>`)):blank('暂无扫描任务','预览地址范围后才能启动。')}${current?`<section><h2>扫描结果 · ${jobState(current)}</h2>${table(['选择','地址 / 媒体','名称 / 分类','结果'],rows.map(r=>{const edit=s.scanEdits[r.index]||{};return `<tr><td><input type="checkbox" data-scan-select="${r.index}" ${edit.selected?'checked':''} ${r.state!=='found'||!canWrite()?'disabled':''} aria-label="选择结果 ${r.index+1}"></td><td>${esc(r.source_url)}<small>${esc(r.probe?.streams?.map(t=>t.codec_name).join(' · ')||'')}</small></td><td><input class="dwrt-kit-input" data-scan-name="${r.index}" value="${esc(edit.name||'')}" aria-label="频道名称 ${r.index+1}"><select class="dwrt-kit-input" data-scan-category="${r.index}" aria-label="分类 ${r.index+1}"><option value="">未分类</option>${categories().map(c=>`<option value="${esc(c.id)}" ${edit.category_id===c.id?'selected':''}>${esc(c.name)}</option>`).join('')}</select></td><td>${esc(r.state==='found'?'发现视频':r.state==='cancelled'?'已停止':REASONS[r.error]||r.error||'探测失败')}</td></tr>`;}))}<div class="iptv-toolbar">${button('预览选中导入','scan-import-preview',!canWrite())}${button('确认选中导入','scan-import',!canWrite()||!s.scanImport||s.scanImport.persisted)}</div>${s.scanImport?table(['行','操作','错误'],s.scanImport.rows.map(r=>`<tr><td>${r.index+1}</td><td>${esc(({skip:'重复跳过',create:'新增',error:'错误'})[r.action])}</td><td>${esc(REASONS[r.error]||r.error||'—')}</td></tr>`)):''}</section>`:''}`;
  }
  const recordingState=r=>({writing:'录制中',pending_archive:'等待归档资源',archiving:'转封装中',verifying:'验证解码',ready:'可播放',archive_failed:'归档失败',interrupted:'服务重启中断',failed:'录制失败',recording:'持续录制',stopping:'正在收尾',stopped:'已停止',error:'录制错误'})[r.state]||r.state;
  const sizeLabel=n=>Number.isFinite(n)?(n/1024/1024).toFixed(1)+' MiB':'—';
  function recordingsPage(){
    const rows=s.recordings.items.filter(r=>(!s.recordFilter||r.channel_id===s.recordFilter)&&(!s.recordDate||(r.start<new Date(s.recordDate+'T00:00:00').getTime()/1000+86400&&r.end>new Date(s.recordDate+'T00:00:00').getTime()/1000))&&(!s.recordSearch||(r.name+' '+(r.title||'')).toLowerCase().includes(s.recordSearch.toLowerCase())));
    return `<div class="iptv-toolbar"><select class="dwrt-kit-input" data-record-filter aria-label="按频道筛选录像"><option value="">全部频道</option>${[...new Map(s.recordings.items.map(r=>[r.channel_id,r.name])).entries()].map(([id,name])=>`<option value="${esc(id)}" ${s.recordFilter===id?'selected':''}>${esc(name)}</option>`).join('')}</select><label>日期<input class="dwrt-kit-input" type="date" data-record-date value="${esc(s.recordDate)}"></label><input class="dwrt-kit-input" data-record-search aria-label="搜索录像" placeholder="搜索录像频道或节目" value="${esc(s.recordSearch)}"><span>已登记占用 ${sizeLabel(s.recordings.used_bytes)}</span>${button('预览过期清理','cleanup-preview',!canWrite())}</div>${s.recordings.captures.length?table(['连续录制','状态','操作'],s.recordings.captures.map(c=>`<tr><td>${esc(c.name)}</td><td>${esc(recordingState(c))}${c.error?`<small>${esc(REASONS[c.error]||c.error)}</small>`:''}</td><td>${button('停止录像','record-stop',!canWrite()||c.state!=='recording',c.id)}</td></tr>`)):''}${s.cleanup?`<section><p>可清理 ${s.cleanup.items.length} 段，预计释放 ${sizeLabel(s.cleanup.bytes)}。锁定和正在写入的录像不会进入清理范围。</p>${button('确认清理','cleanup-commit',!canWrite()||!s.cleanup.items.length)}</section>`:''}${rows.length?table(['频道 / 时间','录像状态','大小','操作'],rows.map(r=>`<tr><td>${esc(r.name)}<small>${date(r.start)} — ${date(r.end)}</small></td><td>${esc(recordingState(r))}${r.locked?' · 已锁定':''}${r.error||r.continuity_error?`<small>${esc(REASONS[r.error]||r.error||r.continuity_error)}</small>`:''}</td><td>${sizeLabel((r.bytes||0)+(r.archive_bytes||0))}</td><td><div class="iptv-actions">${button('播放','record-preview',!canWrite()||!r.media_ready,r.id)}${button(r.locked?'解锁':'锁定','record-lock',!canWrite(),r.id)}${button('重试归档','record-archive',!canWrite()||!['archive_failed','interrupted'].includes(r.state),r.id)}${button('删除','record-delete',!canWrite()||['writing','archiving','verifying'].includes(r.state)||r.locked,r.id)}</div></td></tr>`)):blank('暂无录像','在节目源管理中为已验证的托管频道开始录像。节目预告不会生成视频。')}`;
  }
  function content(){
    if(!s.data)return blank('IPTV 直播',s.error?'服务信息暂不可用。':'正在读取服务信息…');
    if(s.page==='overview'){
      const managed=channels().filter(c=>c.mode==='managed'),running=channels().filter(c=>c.runtime?.process_running);
      return `<div class="iptv-summary">${[['频道',channels().length],['服务器托管',managed.length],['客户端直连',channels().length-managed.length],['运行媒体任务',running.length]].map(([label,value])=>`<div><span>${label}</span><strong>${value}</strong></div>`).join('')}</div><section class="iptv-detail"><h2>媒体服务</h2><dl><dt>运行开关</dt><dd>${s.data.settings?.enabled?'已启用':'已关闭'}</dd><dt>FFmpeg</dt><dd>${caps().ffmpeg_installed?'已安装':'未发现'}</dd><dt>ffprobe</dt><dd>${caps().ffprobe_installed?'已安装':'未发现'}</dd><dt>缓存目录</dt><dd>${esc(s.data.settings?.cache_path||'尚未设置')}</dd><dt>输出方式</dt><dd>HLS · MPEG-TS / fMP4 · 保留源编码</dd></dl></section><section class="iptv-detail"><h2>观看接入</h2><p>已配置 ${collection('viewers').length} 个媒体主体授权。</p><p class="iptv-help">电视和手机使用已有媒体主体及其分类授权访问频道。</p></section>`;
    }
    if(s.page==='channels'){
      const items=channels().filter(c=>(c.name+' '+c.number).toLowerCase().includes(s.query.toLowerCase()));
      return `<div class="iptv-toolbar"><label class="dwrt-kit-field iptv-search" data-dwrt-component="field"><input class="dwrt-kit-input" data-search placeholder="搜索频道名称或编号" aria-label="搜索频道" value="${esc(s.query)}"></label>${button('新建频道','new-channel',!canWrite())}${batchToolbar('channels')}<span>${items.length} 个频道</span></div>${editor()}${snapshotPanel()}${batchResults()}${items.length?table(['选择','频道','方式 / 分类','运行状态','操作'],items.map(c=>`<tr><td>${selected('channels',c.id)}</td><td><strong>${esc(c.name)}</strong><small>${esc(c.number)}</small></td><td>${c.mode==='external'?'客户端直连':'服务器托管'}<small>${esc(categories().find(x=>x.id===c.category_id)?.name||'未分类')}</small></td><td data-runtime="${esc(c.id)}">${c.enabled?stateLabel(c.runtime):'已停用'}${c.runtime?.error?`<small>${esc(REASONS[c.runtime.error]||c.runtime.error)}</small>`:''}</td><td><div class="iptv-actions">${button('编辑','edit-channel',!canWrite(),c.id)}${button('探测','probe',!canWrite()||c.mode==='external'||!caps().http_managed,c.id)}${button('预览','preview',!canWrite()||!c.enabled,c.id)}${button('截图','snapshot',!canWrite()||!caps().snapshots||c.mode==='external'||!c.enabled,c.id)}${button('查看截图','snapshot-view',false,c.id)}${button('常驻拉流','start',!canWrite()||c.mode==='external'||!c.enabled||!caps().http_managed||c.runtime?.manual_hold,c.id)}${button('停止流','stop',!canWrite()||!c.runtime?.process_running,c.id)}${button('开始录像','record-start',!canWrite()||!caps().recordings||c.mode==='external'||!c.enabled,c.id)}${button('删除','delete-channel',!canWrite(),c.id)}</div>${c.runtime?.probe?.streams?`<small>${esc(c.runtime.probe.streams.map(x=>`${x.codec_type}: ${x.codec_name}`).join(' · '))}</small>`:''}</td></tr>`)):blank('暂无频道','添加你有权使用的节目源，然后主动探测或预览。')}`;
    }
    if(s.page==='categories')return programme();
    if(s.page==='recordings'&&caps().recordings)return recordingsPage();
    if(s.page==='viewers')return `<div class="iptv-toolbar">${button('添加观看授权','new-viewer',!canWrite()||!caps().viewer_grants)}${button('批量开通','bulk-viewers',!canWrite())}${batchToolbar('viewers')}${button('导出 CSV','viewers-csv',!canWrite())}${button('查看媒体会话','sessions-load',!canWrite())}</div>${editor()}${batchResults()}${s.sessions.length?table(['媒体会话','来源 / 到期','操作'],s.sessions.map(v=>`<tr><td>${esc(v.principal_id||'管理预览')}<small>${esc(channels().find(c=>c.id===v.channel_id)?.name||v.channel_id)}</small></td><td>${esc(v.origin)} · ${v.recording_id?'录像':'直播'}<small>${date(v.expires_at)}</small></td><td>${button('撤销会话','session-revoke',!canWrite(),v.id)}</td></tr>`)):'仅统计未到期媒体会话，不等于实时观众。'}${collection('viewers').length?table(['选择','媒体主体','分类授权','状态 / 到期','操作'],collection('viewers').map(v=>`<tr><td>${selected('viewers',v.id)}</td><td>${esc(v.name)}<small>${esc(v.principal_id)}</small></td><td>${v.all_categories?'全部分类':esc((v.category_ids||[]).map(id=>categories().find(c=>c.id===id)?.name||(id?'分类不存在':'未分类')).join('、')||'未授权')}</td><td>${v.enabled?'启用':'停用'}<small>${v.expires_at?date(v.expires_at):'不过期'}</small></td><td>${button('编辑','edit-viewer',!canWrite(),v.id)}${button('撤销授权','delete-viewer',!canWrite(),v.id)}</td></tr>`)):blank('暂无观看授权','选择已有媒体主体并设置可看的分类；不会新建登录账户。')}`;
    if(s.page==='settings')return `<section class="iptv-detail"><div class="iptv-fields">${field('enabled','启用 IPTV','checkbox')}${field('cache_path','缓存目录')}${field('max_streams','媒体并发上限（1–4）','number')}${field('max_transcodes','转码并发上限（0 关闭）','number')}${field('segment_seconds','目标片长（秒）','number')}${field('window_segments','直播窗口片数','number')}${field('first_segment_seconds','等待首片超时（秒）','number')}${field('idle_seconds','空闲回收（秒）','number')}${field('cache_limit_mb','每流缓存限额（MiB）','number')}${field('recording_path','录像目录')}${field('recording_limit_mb','录像总限额（MiB）','number')}${field('recording_segment_seconds','单段录像目标时长（秒）','number')}${field('recording_retention_days','录像保留天数','number')}${field('recording_auto_cleanup','自动清理过期录像','checkbox')}</div><p class="iptv-help">缓存必须位于已挂载的数据磁盘，保留至少 128 MiB 空间。目录变更仅供新任务使用，不搬移或删除历史文件。启用自动清理后按保留天数删除已完成且未锁定、未播放的录像。现有流继续使用启动时的设置，停止后重新预览才使用新设置。</p><section data-encoder-list>${encoderPanel()}</section>${button('预检目录与影响','storage-preflight',!canWrite()||s.busy)}${s.storageCheck?table(['目录','检查结果','可用空间'],s.storageCheck.checks.map(c=>`<tr><td>${esc(c.path)}</td><td>${c.valid?'可用于新任务':esc(REASONS[c.error]||c.error)}</td><td>${sizeLabel(c.free_bytes)}</td></tr>`))+`<p>${s.storageCheck.pending_channels.length} 个活动任务保持原目录。</p>`:''}</section>`;
    if(s.page==='scans')return scansPage();
    if(s.page==='inputs')return `<div class="iptv-toolbar">${button('新建专用接入口','input-new',!canWrite()||s.inputSupport!==true||networkPending())}<a class="dwrt-kit-button" data-dwrt-component="button" href="/app/#/network/multicast-service">打开组播服务</a></div><p class="iptv-help">专用端口支持 DHCP、静态 IPv4、PPPoE 和 VLAN。先预检网络影响，再明确应用；保留现有默认路由与 DNS。${s.inputSupport===false?'当前网络服务尚不支持接入口写入。':''}</p><div data-input-task>${inputTaskPanel()}</div>${editor()}${s.inputsError?blank('暂时无法读取接入口',s.inputsError):s.inputs.length?table(['名称 / 配置设备','接入方式','实际设备 / IPv4','可用性','操作'],s.inputs.map(i=>`<tr><td>${esc(i.name)}<small>${esc(i.device)}</small></td><td>${esc(({dhcp:'DHCP',static:'静态',pppoe:'PPPoE'})[i.access_mode]||i.access_mode)}<small>${i.vlan_id?'VLAN '+esc(i.vlan_id):''}</small>${i.option60?`<small>Option 60：${esc(i.option60)}</small>`:''}${i.multicast_source==='carrier'?'<small>组播：独立承载接口</small>':''}${i.igmp_version?`<small>IGMPv${esc(i.igmp_version)} · 实际 ${i.igmp_version_effective?esc(i.igmp_version_effective):'未读到'}</small>`:''}</td><td>${esc(i.runtime_device||'—')}<small>${esc(i.local_address||'未取得地址')}</small></td><td>${i.available?'可用于绑定':esc(REASONS[i.reason]||i.reason)}<small>${Array.isArray(i.interface_groups)?'接口组成员：'+(i.interface_groups.length?i.interface_groups.map(esc).join(' · '):'无'):'接口组成员：未采集'}</small><small>频道接收情况以媒体探测结果为准</small></td><td>${i.role==='iptv'?`<div class="iptv-actions">${button('编辑','input-edit',!canWrite()||s.inputSupport!==true||networkPending(),i.id)}${button('重连','input-reconnect',!canWrite()||!i.enabled||s.inputSupport!==true||networkPending(),i.id)}${button('删除','input-delete',!canWrite()||s.inputSupport!==true||networkPending(),i.id)}</div>`:'已有网络资源 · 只读引用'}</td></tr>`)):blank('暂无网络接口','新建专用接入口，或引用已配置的专用 WAN。')}`;
    const messages={scans:['频道扫描尚未接入','没有启动任何网络扫描。请使用已知的 HTTP(S) 源地址。'],viewers:['观看授权尚未接入','媒体主体与 TV、手机合同仍待衔接，当前没有独立观看账户管理。'],recordings:['回看服务尚未接入','当前没有连续录制或归档文件。频道时移可在直播预览中查看实际窗口。']};
    return blank(...messages[s.page]);
  }
  function render(){
    if(!s.alive)return;
    const confirm=s.confirmation?(ui.confirmationMarkup||window.DWRT_UI_KIT?.confirmationMarkup)?.({id:'iptv-confirm',action:'iptv-confirm',tone:'warning',title:s.confirmation.title,description:s.confirmation.text,cancelLabel:'取消',confirmLabel:'确认',disabled:s.busy}):'';
    if(!root.querySelector('.iptv-shell'))root.innerHTML=`<section class="iptv-shell ${desktop?'':'dwrt-kit-page-surface dwrt-kit-glass-surface'}"><div data-layout></div><div data-savebar></div><div data-confirmation></div><div data-player-host></div></section>`;
    const target=root.querySelector('[data-layout]');
    target.innerHTML=`<aside class="iptv-sidebar dwrt-rail"><div class="dwrt-rail-brand"><img src="/static/images/logo-wide.png" alt="DreamingOS"></div><nav class="dwrt-rail-list" aria-label="IPTV 导航">${PAGES.map(([id,label,ic])=>`<button type="button" class="dwrt-rail-item ${s.page===id?'is-active':''}" data-page="${id}" title="${label}" aria-label="${label}" aria-current="${s.page===id?'page':'false'}"><span class="dwrt-rail-item-icon">${icon(ic)}</span><span class="dwrt-rail-item-text"><span class="dwrt-rail-item-title">${label}</span></span></button>`).join('')}</nav></aside><main class="iptv-main"><header class="iptv-heading"><h1>${PAGES.find(p=>p[0]===s.page)[1]}</h1>${s.conflict?button('核对最新版本','rebase',s.busy):''}${button('刷新','refresh',s.busy)}</header><div data-notice>${s.error||s.notice?`<div class="iptv-notice" role="${s.error?'alert':'status'}">${esc(s.error||s.notice)}</div>`:''}</div><div class="iptv-content">${content()}</div></main>`;
    root.querySelector('[data-savebar]').innerHTML=savebar();root.querySelector('[data-confirmation]').innerHTML=confirm||'';
    ui.mountAll?.(root);root.querySelector('[data-page].is-active')?.scrollIntoView({block:'nearest',inline:'nearest'});
  }
  async function load(){
    const data=await req('overview');if(!s.alive)return;s.data=data;
    if(caps().input_bindings&&(!s.inputsLoaded||s.page==='inputs'))try{s.inputsLoaded=true;s.inputs=(await req('inputs')).items;s.inputsError='';}catch(e){s.inputsError=e.message;}
    if(s.page==='inputs'&&s.inputSupport===null){try{const info=await inputSnapshot('iptv_0000');s.inputSupport=info.domain==='iptv'&&Array.isArray(info.ports);}catch{s.inputSupport=false;}}
    if(networkPending()){await readNetworkTask();const host=root.querySelector('[data-input-task]');if(host){host.innerHTML=inputTaskPanel();ui.mountAll?.(host);}}
    if(caps().recordings)s.recordings=await req('recordings');
    if(s.snapshot&&['queued','running'].includes(s.snapshot.last_attempt?.state))s.snapshot={id:s.snapshot.id,...await req('snapshots/'+s.snapshot.id)};
    if(caps().scans)s.scans=(await req('scans')).items;
    if(s.importer?.fetchId){const job=await req('jobs/'+s.importer.fetchId);s.importer.fetchState=job.state;if(job.state==='complete'){s.importer.text=job.result.text;s.importPreview=job.result;s.importer.fetchId='';render();}else if(['failed','cancelled','interrupted'].includes(job.state)){s.importer.fetchId='';s.error=REASONS[job.error]||job.error;render();}}
    if(s.page==='settings'&&!dirty())startSettings();
    s.error='';
    // Do not replace a live video, focused form, or open confirmation on a poll.
    if(!s.player&&!s.draft&&!s.confirmation&&!s.importer&&!s.order&&!root.querySelector('input:focus,select:focus,textarea:focus'))render();
    const encoderHost=root.querySelector('[data-encoder-list]');if(encoderHost){encoderHost.innerHTML=encoderPanel();ui.mountAll?.(encoderHost);}
    root.querySelectorAll('[data-runtime]').forEach(el=>{const c=channels().find(c=>c.id===el.dataset.runtime);if(c)el.textContent=c.enabled?stateLabel(c.runtime)+(c.runtime?.error?' · '+(REASONS[c.runtime.error]||c.runtime.error):''):'已停用';});
  }
  function startSettings(){s.kind='settings';s.id='';s.draft=clone(s.data.settings);delete s.draft.id;delete s.draft.revision;delete s.draft.can_manage;s.baseline=clone(s.draft);s.baseRevision=s.data.settings.revision;}
  function edit(kind,id=''){
    const row=id?collection(kind).find(x=>x.id===id):null;
    const keys={channels:['name','enabled','position','number','category_id','mode','source_url','hls_container','epg_source_id','epg_id','logo_url','input_id','timeshift_minutes','program_id','rtsp_transport','user_agent','access_url','clear_access_url','video_encoder','audio_encoder','video_bitrate_kbps','audio_bitrate_kbps'],categories:['name','enabled','position'],'epg-sources':['name','enabled','position','url','interval_hours'],viewers:['name','enabled','position','principal_id','all_categories','category_ids','expires_at']}[kind];
    const defaults={name:'',enabled:true,position:0,...(kind==='channels'?{number:0,category_id:'',mode:'managed',source_url:'',hls_container:'mpegts',epg_source_id:'',epg_id:'',logo_url:'',input_id:'',timeshift_minutes:0,program_id:0,rtsp_transport:'',user_agent:'',access_url:'',clear_access_url:false,video_encoder:'copy',audio_encoder:'copy',video_bitrate_kbps:2000,audio_bitrate_kbps:192}:kind==='epg-sources'?{url:'',interval_hours:24}:kind==='viewers'?{principal_id:'',all_categories:false,category_ids:[],expires_at:0}:{})};
    s.draftProbe=null;s.bulkGrant=false;s.conflict=false;s.kind=kind;s.id=id;s.draft=Object.fromEntries(keys.map(k=>[k,row?.[k]??defaults[k]]));
    s.baseline=clone(s.draft);s.baseRevision=row?.revision||0;render();
  }
  function confirm(title,text,run){s.confirmation={title,text,run};render();}
  async function save(){
    if(!canWrite()||!dirty()||s.busy)return;
    if(s.kind==='inputs'){await inputPreflight();return;}
    if(s.order){s.busy=true;try{await req('playlist/reorder','PUT',{kind:s.order.kind,ids:s.order.ids,if_revision:s.order.revision});const list=await req(s.order.kind);if(JSON.stringify(list.items.map(c=>c.id))!==JSON.stringify(s.order.ids))throw new Error('排序回读不一致，更改已保留。');s.order=null;await load();s.notice='顺序已保存。';}catch(e){s.error=e.message;s.conflict=e.code==='revision_conflict';}finally{s.busy=false;render();}return;}
    if(s.bulkGrant){
      const ids=s.draft.principal_ids||[];if(!ids.length){s.error='请选择至少一个媒体主体。';render();return;}
      const {principal_ids,principal_id,name,...grant}=s.draft;
      s.busy=true;try{s.batchResult=await req('viewers/batch','POST',{operation:'create',rows:ids.map(id=>({...grant,principal_id:id,name:s.principals.find(p=>p.id===id)?.name||id}))});
        if(s.batchResult.items.every(r=>r.saved)){s.draft=null;s.baseline=null;s.bulkGrant=false;}else{s.draft.principal_ids=ids.filter((_,i)=>!s.batchResult.items[i].saved);}
        await load();
      }catch(e){s.error=e.message;}finally{s.busy=false;render();}return;
    }
    const current=s.kind==='settings'?s.data.settings:collection(s.kind).find(x=>x.id===s.id);
    const payload={...s.draft,...(current?{if_revision:s.baseRevision}:{})};
    s.busy=true;syncSavebar();
    try{const saved=await req(s.kind+(s.id?'/'+s.id:''),s.id||s.kind==='settings'?'PUT':'POST',payload);
      const canonical=await req(s.kind==='settings'?'settings':s.kind+'/'+saved.record.id);
      for(const [k,v] of Object.entries(s.draft)){
        if(s.kind==='channels'&&(k==='access_url'||k==='clear_access_url'))continue;
        if(JSON.stringify(canonical[k])!==JSON.stringify(v))throw new Error('服务端回读与草稿不一致，草稿已保留。');
      }
      if(s.kind==='channels'&&((s.draft.access_url&&!canonical.has_access_url)||(s.draft.clear_access_url&&canonical.has_access_url)))throw new Error('访问凭据状态回读不一致，草稿已保留。');
      s.conflict=false;s.draft=null;s.baseline=null;s.notice=saved.applied?'配置已保存。':`配置已保存；${saved.pending_channels?.length||0} 个活动任务继续使用原配置。`;await load();
    }catch(e){s.error=e.message;s.conflict=e.code==='revision_conflict';}finally{s.busy=false;render();}
  }
  async function release(session,unloading=false){
    if(!session?.session_id)return;
    if(unloading){const fetcher=window.DWRT_REQUEST?.fetch.bind(window.DWRT_REQUEST)||fetch;void fetcher(A+'sessions/'+encodeURIComponent(session.session_id),{method:'DELETE',credentials:'same-origin',keepalive:true,headers:api.authHeaders?.()||{}}).catch(()=>{});}
    else await req('sessions/'+session.session_id,'DELETE',{});
  }
  async function closePlayer(unloading=false){
    clearTimeout(playerTimer);clearInterval(renew);s.sequence++;
    s.hls?.destroy();s.hls=null;const video=root.querySelector('video');if(video){video.pause();video.removeAttribute('src');video.load();}
    const session=s.player;s.player=null;
    root.querySelector('[data-player-host]')?.replaceChildren();
    await release(session,unloading);
  }
  async function hlsLibrary(){
    if(window.Hls)return window.Hls;
    await new Promise((resolve,reject)=>{let script=document.querySelector('[data-iptv-hls]');if(script){script.addEventListener('load',resolve,{once:true});script.addEventListener('error',reject,{once:true});return;}
      script=document.createElement('script');script.dataset.iptvHls='true';script.src='/static/vendor/iptv-hls/hls.min.js?v=1.6.13';script.onload=resolve;script.onerror=()=>{script.remove();reject(new Error('HLS 播放组件加载失败。'));};document.head.appendChild(script);});return window.Hls;
  }
  function playerStatus(text){const el=root.querySelector('[data-player-status]');if(el)el.textContent=text;}
  async function preview(id,start=0,recording='',offset=0){
    await closePlayer();const seq=++s.sequence;
    const session=await req(recording?'recordings/'+recording+'/preview':'channels/'+id+(start?'/timeshift':'/preview'),'POST',start?{start}:{});session.channel=id;
    if(!s.alive||seq!==s.sequence){await release(session);return;}
    s.player=session;
    root.querySelector('[data-player-host]').innerHTML=`<div class="iptv-player dwrt-kit-modal" role="dialog" aria-label="频道预览"><header><strong>${esc(channels().find(c=>c.id===id)?.name||'频道预览')}</strong><div class="iptv-actions">${button('保存当前画面','frame-capture')}${button('关闭预览','close-player')}</div></header><video controls playsinline muted></video><p data-player-status>等待首片</p>${session.mode==='managed'&&caps().timeshift?`<div class="iptv-toolbar">${button('查看时移窗口','shift-window')}${button('回到直播','live-return')}</div><div data-shift-window></div>`:''}</div>`;
    const video=root.querySelector('video');
    if(offset>0)video.addEventListener('loadedmetadata',()=>{if(Number.isFinite(video.duration)&&offset<video.duration)video.currentTime=offset;else playerStatus('录像偏移已不在文件范围内。');},{once:true});
    video.addEventListener('playing',()=>playerStatus('播放中'));
    video.addEventListener('waiting',()=>playerStatus('缓冲中'));
    video.addEventListener('error',()=>playerStatus('浏览器无法播放此媒体。源协议或编码可能不受支持；其他播放器的能力需单独验证。'));
    const attach=async()=>{
      if(!s.alive||seq!==s.sequence)return;
      if(session.mode==='managed'){
        const row=await req('channels/'+id);const runtime=row.runtime;
        if(!row.enabled||['error','stopped'].includes(runtime?.state))throw new Error(REASONS[runtime?.error]||'频道当前不可播放。');
        if(!runtime?.media_ready){playerTimer=setTimeout(()=>attach().catch(e=>playerStatus(e.message)),1000);return;}
      }
      if(session.mode==='recording'||(session.mode==='external'&&!/\.m3u8(?:$|\?)/i.test(session.url)))video.src=session.url;
      else {
        const Hls=await hlsLibrary();if(seq!==s.sequence)return;
        if(Hls?.isSupported()){
          s.hls=new Hls({enableWorker:true,maxBufferLength:12,manifestLoadingMaxRetry:1,levelLoadingMaxRetry:1,fragLoadingMaxRetry:1});
          s.hls.on(Hls.Events.ERROR,(_,d)=>{if(d.fatal){playerStatus(d.response?.code===401||d.response?.code===403?'预览授权已失效。':'播放失败：'+d.details);s.hls?.stopLoad();}});
          s.hls.loadSource(session.url);s.hls.attachMedia(video);
        }else if(video.canPlayType('application/vnd.apple.mpegurl'))video.src=session.url;
        else throw new Error('浏览器不支持此 HLS 播放方式。');
      }
      playerStatus('切片已就绪，等待播放器');video.play().catch(()=>playerStatus('点击播放开始预览'));
    };
    if(session.session_id)renew=setInterval(()=>req('sessions/'+session.session_id+'/renew','POST',{}).catch(e=>{playerStatus(e.message);video.pause();clearInterval(renew);}),180000);
    try{await attach();}catch(e){playerStatus(e.message);}
  }
  async function action(event){
    const page=event.target.closest('[data-page]');
    if(page){const go=async()=>{await closePlayer();s.page=page.dataset.page;s.batchResult=null;s.draft=null;s.baseline=null;s.order=null;s.importer=null;s.importPreview=null;s.query='';if(s.page==='settings'&&s.data)startSettings();render();};
      if(dirty()||s.importer?.text||s.importer?.base64)confirm('放弃未保存的更改？','切换页面会离开当前编辑。',go);else await go();return;}
    if(event.target.closest('[data-dwrt-confirm-cancel], [data-dwrt-modal-close]')){s.confirmation=null;render();return;}
    if(event.target.closest('[data-dwrt-confirm-accept]')){const run=s.confirmation?.run;s.confirmation=null;if(run)await run();render();return;}
    if(event.target.closest('[data-dwrt-savebar-save]')){await save();return;}
    if(event.target.closest('[data-dwrt-savebar-discard]')){s.order=null;s.draft=s.baseline?clone(s.baseline):null;s.inputPlan=null;render();return;}
    const tab=event.target.closest('[data-guide-tab]');if(tab){if(unsaved()){s.error='请先保存、撤销或关闭当前编辑。';render();return;}s.tab=tab.dataset.guideTab;s.draft=null;render();return;}
    const target=event.target.closest('[data-action]');if(!target)return;
    const id=target.dataset.id,act=target.dataset.action;
    if(s.busy)return;
    if(act==='rebase'){
      if(s.order){const latest=await req(s.order.kind);const present=new Set(latest.items.map(c=>c.id));s.order.ids=s.order.ids.filter(id=>present.has(id));for(const c of latest.items)if(!s.order.ids.includes(c.id))s.order.ids.push(c.id);s.order.revision=latest.revision;s.data[s.order.kind]=latest;}
      else if(s.kind==='inputs'){const latest=await inputSnapshot(s.id),next=inputDraft(latest.config);for(const key of Object.keys(s.draft))if(JSON.stringify(s.draft[key])===JSON.stringify(s.baseline[key]))s.draft[key]=next[key];s.baseline=clone(next);s.inputContext=latest;s.baseRevision=latest.revision;s.inputPlan=null;}
      else if(s.draft){const latest=await req(s.kind==='settings'?'settings':s.kind+'/'+s.id);for(const key of Object.keys(s.draft))if(JSON.stringify(s.draft[key])===JSON.stringify(s.baseline[key]))s.draft[key]=clone(latest[key]??s.baseline[key]);s.baseline=Object.fromEntries(Object.keys(s.draft).map(k=>[k,clone(latest[k]??s.baseline[k])]));s.baseRevision=latest.revision;}
      s.conflict=false;s.error='';s.notice='已读取最新版本；你修改的字段保留在草稿中，请核对后保存。';render();
    }
    else if(act==='refresh'){await load();if(!s.player)render();}
    else if(act==='input-new'||act==='input-edit'){if(dirty())throw new Error('请先保存或撤销当前草稿。');await editInput(act==='input-edit'?id:'');}
    else if(act==='input-delete'||act==='input-reconnect'){if(dirty())throw new Error('请先保存或撤销当前草稿。');await editInput(id);await inputPreflight(act==='input-delete'?'delete':'reconnect');}
    else if(act==='input-apply'){const plan=s.inputPlan;if(!plan)return;confirm('应用接入口网络更改？',`本接入口将${plan.body.operation==='delete'?'被删除':'短暂中断'}，影响 ${plan.result.channel_references?.length||0} 个引用频道；90 秒内需保留更改，否则自动恢复。`,()=>applyInput(plan));}
    else if(act==='input-task-refresh'){await readNetworkTask();render();}
    else if(act==='input-confirm'||act==='input-rollback'){const task=s.networkTask;if(!task?.task_id)return;s.busy=true;try{await req('/api/v1/config/'+(act==='input-confirm'?'confirm':'rollback'),'POST',{task_id:task.task_id});await readNetworkTask();await load();}finally{s.busy=false;render();}}

    else if(['batch-enable','batch-disable','batch-delete'].includes(act)){
      if(dirty())throw new Error('请先保存或撤销当前草稿。');
      const kind=id,rows=collection(kind).filter(r=>s.selected[kind].includes(r.id)).map(r=>({id:r.id,if_revision:r.revision}));
      confirm('处理选中的 '+rows.length+' 项？',act==='batch-delete'?'将删除选中的频道或授权；历史录像保留。':'停用会使旧媒体地址在后续请求时失效。',async()=>{
        s.batchResult=await req(kind+'/batch','POST',{operation:act==='batch-delete'?'delete':'update',rows,patch:{enabled:act==='batch-enable'}});
        s.selected[kind]=s.batchResult.items.filter(r=>!r.saved).map(r=>r.id);await load();render();
      });
    }
    else if(act==='bulk-viewers'){
      if(dirty())throw new Error('请先保存或撤销当前草稿。');s.principals=(await req('principals')).items;edit('viewers');s.bulkGrant=true;s.draft.principal_ids=[];s.baseline=clone(s.draft);render();
    }
    else if(act==='snapshot'||act==='snapshot-view'){if(act==='snapshot')await req('snapshots/'+id,'POST',{});s.snapshot={id,...await req('snapshots/'+id)};render();}
    else if(act==='snapshot-close'){s.snapshot=null;render();}
    else if(act==='encoder-probe'||act==='encoder-stop'){await req('encoders/'+id+'/probe',act==='encoder-probe'?'POST':'DELETE',{});await load();render();}
    else if(act==='storage-preflight'){s.storageCheck=await req('settings/preflight','POST',{...s.draft,if_revision:s.baseRevision});render();}
    else if(act==='sessions-load'){s.sessions=(await req('sessions')).items;render();}
    else if(act==='session-revoke'){confirm('撤销这个媒体会话？','后续媒体请求将被拒绝；不注销其登录账户或其他观看端。',async()=>{await req('sessions/'+id+'/revoke','POST',{confirm:true});s.sessions=(await req('sessions')).items;render();});}
    else if(act==='viewers-csv'){const data=await req('exports/viewers.csv');const url=URL.createObjectURL(new Blob(['\ufeff'+data.text],{type:'text/csv;charset=utf-8'}));const link=document.createElement('a');link.href=url;link.download='iptv-viewers.csv';link.click();setTimeout(()=>URL.revokeObjectURL(url),1000);s.notice='观看授权 CSV 已导出。';render();}
    else if(act==='new-channel'||act==='new-category'){if(dirty()){s.error='请先保存或撤销当前草稿。';render();return;}edit(act==='new-channel'?'channels':'categories');}
    else if(act==='edit-channel'||act==='edit-category'){if(dirty()){s.error='请先保存或撤销当前草稿。';render();return;}edit(act==='edit-channel'?'channels':'categories',id);}
    else if(act==='close-editor'){const close=()=>{s.draft=null;s.baseline=null;s.inputPlan=null;render();};if(dirty())confirm('放弃更改？','当前草稿尚未保存。',close);else close();}
    else if(act==='delete-channel'||act==='delete-category'){const kind=act==='delete-channel'?'channels':'categories';const record=(kind==='channels'?channels():categories()).find(x=>x.id===id);
      confirm('删除'+record.name+'？',kind==='channels'?'后续观看请求将被拒绝。此操作不删除历史录像。':'有频道引用的分类不能删除。',async()=>{await req(kind+'/'+id,'DELETE',{if_revision:record.revision});await load();});}
    else if(['new-epg','edit-epg','new-viewer','edit-viewer'].includes(act)){
      if(dirty()){s.error='请先保存或撤销当前草稿。';render();return;}
      if(act.includes('viewer'))s.principals=(await req('principals')).items;
      edit(act.includes('viewer')?'viewers':'epg-sources',act.startsWith('edit')?id:'');
    }
    else if(act==='delete-epg'||act==='delete-viewer'){
      const kind=act==='delete-epg'?'epg-sources':'viewers',v=collection(kind).find(v=>v.id===id);
      confirm('删除'+v.name+'？',kind==='viewers'?'旧媒体地址会在后续请求时失效。':'已有频道映射时将拒绝删除。',async()=>{await req(kind+'/'+id,'DELETE',{if_revision:v.revision});await load();});
    }
    else if(act==='refresh-epg'){await req('epg-sources/'+id+'/refresh','POST',{});s.notice='已受理节目表更新。';await load();render();}
    else if(act==='guide-load'){const id=root.querySelector('[data-guide-channel]').value;if(!id)return;const data=await req('epg/'+id);s.epgGuide={channel:id,items:data.items};render();}
    else if(act==='open-import'){if(dirty())throw new Error('请先保存或撤销当前草稿。');s.draft=null;s.importer={format:'m3u',duplicates:'skip',text:'',base64:''};s.importPreview=null;render();}
    else if(act==='close-import'){const close=()=>{s.importer=null;s.importPreview=null;render();};if(s.importer?.text||s.importer?.base64)confirm('放弃导入草稿？','已选择的文件和预览内容将关闭，已导入的频道保留。',close);else close();}
    else if(act==='import-fetch'){if(!s.importer?.url)throw new Error('请填写列表 URL。');const job=await req('imports/fetch','POST',{url:s.importer.url,format:s.importer.format,confirm:true});s.importer.fetchId=job.id;s.importer.fetchState=job.state;s.importPreview=null;render();}
    else if(act==='scan-preview'){s.scanPlan=await req('scans/preview','POST',s.scanDraft);render();}
    else if(act==='scan-start'){const plan=clone(s.scanDraft);confirm('开始扫描这 '+s.scanPlan.count+' 个地址？','将主动连接已预览范围，单路占用媒体探测资源。',async()=>{const job=await req('scans','POST',{...plan,confirm:true});s.scanId=job.id;s.scanEdits={};s.scanPlan=null;await load();});}
    else if(act==='scan-open'){s.scanId=id;s.scanEdits={};s.scanImport=null;render();}
    else if(act==='scan-stop'){await req('scans/'+id+'/stop','POST',{});s.notice='已请求停止，等待当前探测释放。';await load();}
    else if(act==='scan-delete'){confirm('删除扫描记录？','只删除本次任务记录，保留已导入的频道。',async()=>{await req('scans/'+id,'DELETE',{});if(s.scanId===id)s.scanId='';await load();});}
    else if(act==='scan-import-preview'||act==='scan-import'){const rows=Object.entries(s.scanEdits).filter(([,v])=>v.selected).map(([index,v])=>({index:Number(index),name:v.name||'',category_id:v.category_id||''}));if(!rows.length)throw new Error('请至少选择一个有视频的结果。');s.scanImport=await req('scans/'+s.scanId+(act==='scan-import'?'/import':'/import-preview'),'POST',{rows,...(act==='scan-import'?{if_revision:s.scanImport.base_revision}:{})});await load();render();}
    else if(act==='import-preview'||act==='import-commit'){
      if(!s.importer)return;
      if(act==='import-commit'&&!s.importPreview)return;
      s.busy=true;try{s.importPreview=await req(act==='import-preview'?'imports/preview':'imports/commit','POST',{format:s.importer.format,duplicates:s.importer.duplicates,...(s.importer.format==='xlsx'?{base64:s.importer.base64}:{text:s.importer.text}),...(act==='import-commit'?{if_revision:s.importPreview.base_revision}:{})});
        if(s.importPreview.persisted){s.notice=`已保存 ${s.importPreview.saved} 个频道；逐行结果如下。`;await load();}
      }finally{s.busy=false;render();}
    }
    else if(act==='xlsx-template'||act==='xlsx-export'){const data=await req(act==='xlsx-template'?'exports/template':'exports/xlsx');const bytes=Uint8Array.from(atob(data.base64),c=>c.charCodeAt(0));const url=URL.createObjectURL(new Blob([bytes],{type:'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'}));const a=document.createElement('a');a.href=url;a.download=data.filename;a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);}
    else if(act==='export-m3u'){const data=await req('exports/m3u');const url=URL.createObjectURL(new Blob([data.text],{type:'audio/x-mpegurl'}));const link=document.createElement('a');link.href=url;link.download='iptv-direct.m3u';link.click();setTimeout(()=>URL.revokeObjectURL(url),1000);s.notice=`已导出直连列表；跳过 ${data.omitted_managed_or_disabled||0} 个托管或停用频道、${data.omitted_credential_sources||0} 个带访问凭据的频道。`;render();}
    else if(['order-up','order-down','category-up','category-down'].includes(act)){
      if(s.draft||s.importer)throw new Error('请先关闭当前编辑，再调整频道顺序。');
      const kind=act.startsWith('category')?'categories':'channels';if(s.order&&s.order.kind!==kind)throw new Error('请先保存或撤销当前排序。');
      if(!s.order)s.order={kind,ids:collection(kind).map(c=>c.id),revision:s.data[kind].revision};
      const at=s.order.ids.indexOf(id),next=at+(act.endsWith('-up')?-1:1);if(next>=0&&next<s.order.ids.length)[s.order.ids[at],s.order.ids[next]]=[s.order.ids[next],s.order.ids[at]];render();
    }
    else if(act==='draft-probe'){
      if(s.draftProbe?.operation_id)await req('probes/'+s.draftProbe.operation_id,'DELETE');
      s.draftProbe=await req('probes','POST',clone(s.draft));
      root.querySelector('[data-draft-probe-status]').textContent='已受理当前草稿；未保存频道。';
      root.querySelector('[data-action=draft-probe-result]').disabled=false;root.querySelector('[data-action=draft-probe-stop]').disabled=false;
    }
    else if(act==='draft-probe-result'){
      const result=await req('probes/'+s.draftProbe.operation_id);Object.assign(s.draftProbe,result);
      root.querySelector('[data-draft-probe-status]').textContent=stateLabel(result)+(result.error?' · '+(REASONS[result.error]||result.error):'')+(result.probe?.streams?' · '+result.probe.streams.map(t=>t.codec_type+': '+t.codec_name).join(' / '):'');
    }
    else if(act==='draft-probe-stop'){await req('probes/'+s.draftProbe.operation_id,'DELETE');root.querySelector('[data-draft-probe-status]').textContent='探测已停止；草稿保留。';}
    else if(act==='probe'){await req('channels/'+id+'/probe','POST',{});s.notice='已受理探测，请等待实际媒体结果。';await load();render();}
    else if(act==='preview')await preview(id);
    else if(act==='record-start'){const channel=channels().find(c=>c.id===id);confirm('开始连续录像？','将保持频道拉流，并在所选录像磁盘持续写入；归档与直播共用媒体预算。关闭预览不会停止录像。',async()=>{await req('captures/'+id+'/start','POST',{confirm:true,if_revision:channel.revision});await load();render();});}
    else if(act==='record-stop'){await req('captures/'+id+'/stop','POST',{});await load();render();}
    else if(act==='guide-recording'){const r=s.recordings.items.find(r=>r.id===id);if(!r)throw new Error('录像已不可用，请刷新节目表。');await preview(r.channel_id,0,id,Number(target.dataset.offset)||0);}
    else if(act==='record-preview'){const r=s.recordings.items.find(r=>r.id===id);await preview(r.channel_id,0,id);}
    else if(act==='record-lock'){const r=s.recordings.items.find(r=>r.id===id);await req('recordings/'+id,'PUT',{if_revision:r.revision,locked:!r.locked});await load();render();}
    else if(act==='record-delete'){const r=s.recordings.items.find(r=>r.id===id);confirm('删除这段录像？','将永久删除该段原始 TS 和归档 MP4，共 '+sizeLabel((r.bytes||0)+(r.archive_bytes||0))+'；正在播放的录像会被拒绝删除。',async()=>{await req('recordings/'+id,'DELETE',{if_revision:r.revision,confirm:true});await load();render();});}
    else if(act==='record-archive'){const r=s.recordings.items.find(r=>r.id===id);await req('recordings/'+id+'/archive','POST',{if_revision:r.revision});await load();render();}
    else if(act==='cleanup-preview'){s.cleanup=await req('recordings/cleanup-preview','POST',{});render();}
    else if(act==='cleanup-commit'){const items=s.cleanup.items.map(r=>({id:r.id,revision:r.revision}));confirm('清理这 '+items.length+' 段过期录像？','只清理刚才预览的录像；状态或锁定已变化的条目将保留。',async()=>{const result=await req('recordings/cleanup','POST',{items,confirm:true});s.cleanup=null;s.notice='已删除 '+result.items.filter(r=>r.deleted).length+' 段，保留 '+result.items.filter(r=>!r.deleted).length+' 段。';await load();render();});}
    else if(act==='start')confirm('保持此频道拉流？','即使关闭预览也会继续接收节目并保留配置的时移窗口，占用媒体预算和磁盘；可用停止流结束。',async()=>{await req('channels/'+id+'/start','POST',{});await load();});
    else if(act==='shift-window'){const win=await req('channels/'+s.player.channel+'/timeshift');const first=Math.ceil(win.start),last=Math.floor(win.end)-1;root.querySelector('[data-shift-window]').innerHTML=`<p>${date(win.start)} — ${date(win.end)}${win.missing_segments?' · 缺失 '+win.missing_segments+' 片':''}</p><label class="iptv-field">选择时间<input type="range" min="${first}" max="${last}" value="${Math.max(first,last-6)}" data-shift-value><output data-shift-label>${date(Math.max(first,last-6))}</output></label>${button('播放所选时间','shift-play')}`;}
    else if(act==='shift-play'){const start=Number(root.querySelector('[data-shift-value]')?.value);if(start)await preview(s.player.channel,start);}
    else if(act==='live-return')await preview(s.player.channel);
    else if(act==='stop')confirm('停止此频道的全部观看与录制？','将停止此频道的共享流，影响全部观看者与进行中的录像。已写入的录像会收尾保留。',async()=>{await req('channels/'+id+'/stop','POST',{confirm:true});await load();});
    else if(act==='frame-capture'){
      const video=root.querySelector('video');if(!video||video.readyState<2||!video.videoWidth)throw new Error('尚未解码出画面，无法截图。');
      const canvas=document.createElement('canvas');canvas.width=video.videoWidth;canvas.height=video.videoHeight;
      try{canvas.getContext('2d').drawImage(video,0,0);const blob=await new Promise(resolve=>canvas.toBlob(resolve,'image/png'));if(!blob)throw new Error();
        const url=URL.createObjectURL(blob),link=document.createElement('a');link.href=url;link.download='iptv-'+new Date().toISOString().replace(/[:.]/g,'-')+'.png';link.click();setTimeout(()=>URL.revokeObjectURL(url),1000);
      }catch(e){throw new Error('当前媒体不允许浏览器读取画面，未生成截图。');}
    }
    else if(act==='close-player')await closePlayer();
  }
  const onClick=e=>{action(e).catch(error=>{s.error=error.message;if(s.player)playerStatus(error.message);else render();});};
  root.addEventListener('click',onClick);
  const onInput=e=>{
    if(e.target.dataset.selectKind){const kind=e.target.dataset.selectKind,id=e.target.dataset.selectId;const selected=new Set(s.selected[kind]);e.target.checked?selected.add(id):selected.delete(id);s.selected[kind]=[...selected];render();return;}
    if(e.target.dataset.bulkPrincipal&&s.bulkGrant){const ids=new Set(s.draft.principal_ids);e.target.checked?ids.add(e.target.dataset.bulkPrincipal):ids.delete(e.target.dataset.bulkPrincipal);s.draft.principal_ids=[...ids];syncSavebar();return;}

    if(e.target.hasAttribute('data-record-date')){s.recordDate=e.target.value;render();return;}
    if(e.target.hasAttribute('data-record-search')){s.recordSearch=e.target.value;const pos=e.target.selectionStart;render();const next=root.querySelector('[data-record-search]');next.focus();next.setSelectionRange(pos,pos);return;}
    if(e.target.hasAttribute('data-record-filter')){s.recordFilter=e.target.value;render();return;}
    if(e.target.hasAttribute('data-shift-value')){root.querySelector('[data-shift-label]').textContent=date(Number(e.target.value));return;}
    if(e.target.dataset.scanField){s.scanDraft[e.target.dataset.scanField]=e.target.type==='number'?Number(e.target.value):e.target.value;s.scanPlan=null;root.querySelector('[data-action=scan-start]')?.setAttribute('disabled','');return;}
    for(const [attribute,key] of [['scanSelect','selected'],['scanName','name'],['scanCategory','category_id']])if(e.target.dataset[attribute]!==undefined){const index=e.target.dataset[attribute];s.scanEdits[index]??={};s.scanEdits[index][key]=key==='selected'?e.target.checked:e.target.value;s.scanImport=null;root.querySelector('[data-action=scan-import]')?.setAttribute('disabled','');return;}

    if(e.target.hasAttribute('data-grant-category')&&s.draft){const values=new Set(s.draft.category_ids);e.target.checked?values.add(e.target.dataset.grantCategory):values.delete(e.target.dataset.grantCategory);s.draft.category_ids=[...values];syncSavebar();return;}
    if(e.target.dataset.importField&&s.importer){s.importer[e.target.dataset.importField]=e.target.value;s.importPreview=null;if(e.target.dataset.importField==='format')render();return;}
    const key=e.target.dataset.field;if(key&&s.draft){s.storageCheck=null;s.inputPlan=null;root.querySelector('[aria-label="网络变更预检"]')?.remove();s.draft[key]=e.target.type==='checkbox'?e.target.checked:e.target.type==='number'?Number(e.target.value):e.target.value;syncSavebar();if(s.kind==='inputs'&&['access_mode','vlan_enabled','multicast_source','carrier_access_mode'].includes(key)){if(key==='access_mode'&&s.draft.access_mode!=='pppoe'&&'multicast_source' in s.draft)s.draft.multicast_source='session';render();}}
    if(e.target.matches('[data-search]')){s.query=e.target.value;const pos=e.target.selectionStart;render();const input=root.querySelector('[data-search]');input?.focus();input?.setSelectionRange(pos,pos);}};
  root.addEventListener('input',onInput);
  const beforeLeave=e=>{if(unsaved()||s.busy){e.preventDefault();e.returnValue='';}};
  window.addEventListener('beforeunload',beforeLeave);
  let previousHash=location.hash;
  const beforeHash=e=>{if((unsaved()||s.busy)&&!window.confirm('有未保存的 IPTV 更改，放弃并离开？')){history.replaceState(null,'',previousHash);e.stopImmediatePropagation();}else previousHash=location.hash;};
  window.addEventListener('hashchange',beforeHash,true);
  const onChange=async e=>{if(!e.target.matches('[data-import-file]'))return;const file=e.target.files?.[0];if(!file)return;const xlsx=/\.xlsx$/i.test(file.name);if(file.size>(xlsx?1024*1024:512*1024)){s.error=xlsx?'XLSX 最大 1 MiB。':'播放列表最大 512 KiB。';render();return;}if(xlsx){const bytes=new Uint8Array(await file.arrayBuffer());let binary='';for(let i=0;i<bytes.length;i+=8192)binary+=String.fromCharCode(...bytes.subarray(i,i+8192));s.importer.base64=btoa(binary);s.importer.filename=file.name;s.importer.format='xlsx';}else{s.importer.text=await file.text();s.importer.format=/\.txt$/i.test(file.name)?'txt':'m3u';}s.importPreview=null;render();};
  root.addEventListener('change',onChange);
  const visibility=()=>{if(s.player&&(document.hidden||(window.frameElement&&!window.frameElement.getClientRects().length)))void closePlayer().catch(()=>{});};
  document.addEventListener('visibilitychange',visibility);
  const keydown=e=>{const modal=root.querySelector('[data-confirmation] [role=dialog]')||root.querySelector('[data-player-host] [role=dialog]');if(!modal)return;if(e.key==='Escape'){e.preventDefault();if(s.confirmation){s.confirmation=null;render();}else void closePlayer();}if(e.key==='Tab'){const nodes=[...modal.querySelectorAll('button:not(:disabled),video[controls],input,select')];if(!nodes.length)return;const at=nodes.indexOf(document.activeElement);if(e.shiftKey&&at<=0){e.preventDefault();nodes.at(-1).focus();}else if(!e.shiftKey&&(at<0||at===nodes.length-1)){e.preventDefault();nodes[0].focus();}}};
  root.addEventListener('keydown',keydown);
  for(const [id,href] of [['iptv-rail','/static/desktop/dwrt-rail.css?v=20261008-desktop-material-01'],['iptv-style','/plugins/native/iptv.css?v='+VERSION]])if(!document.getElementById(id)){const link=document.createElement('link');link.id=id;link.rel='stylesheet';link.href=href;document.head.appendChild(link);}
  if(!document.querySelector('script[data-iptv-foreground]')){const script=document.createElement('script');script.dataset.iptvForeground='true';script.src='/static/desktop/glass-foreground.js?v=20261008-desktop-material-01';document.head.appendChild(script);}
  root.classList.add('iptv-route');root.classList.toggle('iptv-traditional',!desktop);render();load().catch(e=>{s.error=e.message;render();});
  poll=setInterval(()=>{visibility();if(!document.hidden&&!s.busy)load().catch(e=>{s.error=e.message;if(!s.player&&!s.draft)render();});},5000);
  return {unmount(){s.alive=false;clearInterval(poll);clearInterval(renew);clearTimeout(playerTimer);controller.abort();window.removeEventListener('beforeunload',beforeLeave);window.removeEventListener('hashchange',beforeHash,true);document.removeEventListener('visibilitychange',visibility);root.removeEventListener('change',onChange);root.removeEventListener('keydown',keydown);root.removeEventListener('click',onClick);root.removeEventListener('input',onInput);void closePlayer(true);ui.unmount?.(root);root.classList.remove('iptv-route','iptv-traditional');}};
}
