// Independently authored DreamingWrt diagnostic UI; shared by both hosts.
const VERSION='20261003-ad-analyzer-10';
const API='/api/v1/diagnostics/ad-analyzer/';
const esc=(v)=>String(v??'').replace(/[&<>"']/g,(c)=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const when=(v)=>v?new Date(v*1000).toLocaleString('zh-CN'):'未记录';
const modeName=(v)=>v==='false_positive'?'查误伤':'找广告';
const names={applied:'已应用',reverted:'已撤回',reverting:'正在撤回',awaiting_feedback:'等待本轮反馈',verified_candidate:'单条复测有效',unlocated:'尚未定位',ended:'已结束',replaced_manually:'已改为手动试验',capturing:'采集中',degraded:'采集来源暂时不可用',stopped:'已停止',expired:'采集已到期',failed:'采集已中断',ready:'可用',unavailable:'未接通',requires_action:'需准备日志',idle_or_unavailable:'近期无日志，来源待确认',none:'未发现明显线索',low:'少量线索',suspicious:'值得排查',high:'较强线索',saved:'报告已保存',not_finalized:'报告尚未生成'};
const sourceNames={dns:'DNS 查询',conn:'连接线索',tls_sni:'TLS SNI',http_host:'HTTP Host',udp443_ip:'UDP 443'};
const reasonNames={native_dns_provider_not_ready:'原生 DNS 设备规则服务未就绪',provider_revision_conflict:'过滤规则版本已变化，请刷新预览后重试',provider_conflict:'存在 DNS 放行不能覆盖的连接层阻断',round_conflict:'本轮已更新或到期，请读取最新状态',trial_expired:'试验已到期，请重新应用',session_ended:'会话已结束，请新建分析',exact_device_allow_unavailable:'无法按设备精确放行，也不能覆盖全局 DNS 或其他策略的拦截',shared_address_isolation_unavailable:'按目标 IP 执行时可能影响共享地址上的其他域名',query_log_not_ready:'DNS 查询日志尚未就绪',exact_device_domain_provider_unavailable:'当前执行点不能保证设备精确域名隔离，试验与永久保存暂不可用。',resource_owner_required:'只有创建该会话的操作者可以修改',revision_conflict:'版本已变化，已保留草稿，请重新读取后重试',device_identity_changed:'目标地址的租约已变化，请重新选择设备',report_target_mismatch:'历史候选的设备或模式不一致',query_log_unavailable:'查询工作日志不可读取',no_recent_log_events:'近期没有日志，不能据此判断设备无广告',log_rotated_or_truncated:'日志已轮换或截断，部分区间可能缺失',session_byte_limit:'会话已达到字节上限',domain_evidence_limit:'单域名的应答明细已达到保留上限',capture_end_backlog:'停止时存在未读取日志，报告已标记截断',service_restart:'采集服务重启，报告保留重启前快照',observe_ttl:'达到采集时限',user_stopped:'手动停止',resource_limit:'达到资源上限',target_identity_changed:'目标 IP 的设备租约已失效或变化，采集已停止',dhcp_identity_lost_or_changed:'目标设备归属无法继续确认'};
const describe=(code)=>reasonNames[code]||names[code]||code;
const freshId=()=>crypto.randomUUID();

export function mount(context={}) {
  const root=context.root||document.getElementById('routePreview');
  const ui={...(window.DWRT_UI_KIT||{}),...(context.ui||{})};
  const desktop=document.body.classList.contains('ad-analyzer-app');
  // The traditional shell only loads menu styles under /static/css/.
  if(!document.querySelector('link[href*="/plugins/native/ad-analyzer.css"]')){
    const style=document.createElement('link');style.rel='stylesheet';style.href='/plugins/native/ad-analyzer.css?v='+VERSION;document.head.appendChild(style);
  }
  const state={live:true,tab:'workbench',busy:false,loading:true,sessionsLoaded:false,reportsLoaded:false,cap:null,sessions:[],selected:'',session:null,obs:null,rows:[],offset:0,q:'',level:'',blocked:false,connection:false,parent:false,unmatchedConnections:false,clients:[],target:'',deviceIp:'',mode:'find_ads',ttl:600,drafts:new Map(),selectedRows:new Map(),evidence:'',notice:'',error:'',lastSuccess:0,reports:[],reportTotal:0,reportOffset:0,reportIp:'',reportMode:'',report:null,reportLabel:'',reportDomainOffset:0,reuse:false,preview:null,trialTtl:120,baseline:false,scopeAll:false,group:false};
  const requests=new Set(),pendingWrites=new Map();let inflight=false,poll,filterTimer,confirmation=null,seenSeq=0,writeEpoch=0;
  const writable=()=>state.cap?.permissions?.operate===true;
  const sessionWritable=()=>writable()&&state.session?.can_operate===true;
  const decisions=()=>{if(!state.drafts.has(state.selected))state.drafts.set(state.selected,new Map());return state.drafts.get(state.selected);};
  const selection=()=>{if(!state.selectedRows.has(state.selected))state.selectedRows.set(state.selected,new Set());return state.selectedRows.get(state.selected);};
  const trialActive=()=>state.session?.trial?.apply_state==='applied'&&state.session.trial.expires_at>Date.now()/1000;
  const canTrial=(action)=>sessionWritable()&&!state.session?.ended&&state.session?.trial_supported&&state.cap?.actions?.['can_trial_'+action];
  const scope=()=>state.scopeAll?{type:'all'}:{type:'device',device_id:state.session.device_id};
  const draftRules=()=>[...decisions()].map(([domain,action])=>({domain,action,match:'exact'}));
  const dirty=()=>[...state.drafts.values()].some((m)=>m.size)||!!state.report&&state.reportLabel!==state.report.label;
  const icon=(id)=>window.DWRT_MENU_ICON?.[id]||'';
  const btn=(label,action,disabled=false,more='')=>`<button type="button" class="dwrt-kit-button" data-dwrt-component="button" data-ada-action="${action}" ${disabled||state.busy?'disabled':''} ${more}>${esc(label)}</button>`;
  const field=(label,content,classes='')=>`<label class="ada-field dwrt-kit-field ${classes}" data-dwrt-component="field"><span>${esc(label)}</span>${content.replace(/<input /g,'<input class="dwrt-kit-input" ').replace(/<select /g,'<select class="dwrt-kit-input dwrt-kit-select" ')}</label>`;
  const opt=(value,label,current)=>`<option value="${esc(value)}" ${value===current?'selected':''}>${esc(label)}</option>`;
  function errorText(e) {
    if(e.code&&reasonNames[e.code])return reasonNames[e.code];
    const prefix=e.status===401?'登录已失效':e.status===403?'权限不足':[404,405,501].includes(e.status)?'当前设备尚未接入此接口':e.status>=500?'后端读取失败':!e.status?'网络连接失败':'';
    return [prefix,e.message].filter(Boolean).join('：');
  }
  async function request(path,method='GET',body) {
    const controller=new AbortController();requests.add(controller);
    try {
      const response=await (window.DWRT_REQUEST?.fetch||window.fetch.bind(window))(path.startsWith('/api/')?path:API+path,{method,signal:controller.signal,headers:body?{'Content-Type':'application/json'}:{},body:body?JSON.stringify(body):undefined});
      let payload;try{payload=await response.json();}catch(_){const e=new Error('响应不是有效 JSON');e.status=response.status;throw e;}
      const data=payload.data??payload;
      if(!response.ok||data.ok===false||payload.code!==undefined&&payload.code!==2000){const err=data.error||payload.error;const e=new Error(typeof err==='object'?err.message:typeof err==='string'?err:payload.message||`HTTP ${response.status}`);e.status=response.status;e.code=err?.code;throw e;}
      return data;
    } finally{requests.delete(controller);}
  }
  function tabs() {
    const items=[['workbench','分析工作台','monitor'],['history','历史报告','log_center']];
    if(desktop)return `<nav class="dwrt-rail" aria-label="广告分析导航"><div class="dwrt-rail-brand"><img src="/static/images/logo-wide.png" alt="DreamingOS"></div><div class="dwrt-rail-list">${items.map(([id,label,ic])=>`<button class="dwrt-rail-item ${state.tab===id?'is-active':''}" data-ada-action="tab" data-tab="${id}" aria-current="${state.tab===id?'page':'false'}" aria-label="${label}"><span class="dwrt-rail-item-icon">${icon(ic)||esc(label.slice(0,1))}</span><span class="dwrt-rail-item-text">${label}</span></button>`).join('')}</div><div class="dwrt-rail-foot">按需采集 · 到期停止</div></nav>`;
    return `<div class="dwrt-kit-tabs dwrt-kit-page-tabs ada-tabs" data-dwrt-component="tabs" role="tablist" aria-label="广告分析">${items.map(([id,label])=>`<button class="dwrt-kit-tab ${state.tab===id?'is-active':''}" role="tab" data-value="${id}" data-ada-action="tab" data-tab="${id}" aria-selected="${state.tab===id}">${label}</button>`).join('')}</div>`;
  }
  function setup() {
    const canStart=state.cap?.actions?.can_observe===true;
    return `<div class="ada-toolbar"><p class="ada-muted">定位设备上的广告请求，或排查过滤造成的访问异常。</p>${btn('刷新','refresh')}</div><form id="ada-create" class="ada-filters">
      ${field('目标设备',`<select id="ada-target" data-field="target" ${!writable()?'disabled':''}>${opt('','手动输入 IP（按现有租约识别）',state.target)}${state.clients.map((c)=>opt(c.mac,`${c.name||c.hostname||c.device_name||c.ip} · ${c.ip}`,state.target)).join('')}</select>`)}
      ${field('设备 IP',`<input id="ada-ip" data-field="deviceIp" value="${esc(state.deviceIp)}" placeholder="例如 192.168.30.16" ${state.target||!writable()?'readonly':''} autocomplete="off">`)}
      ${field('分析模式',`<select id="ada-mode" data-field="mode" ${!writable()?'disabled':''}>${opt('find_ads','找广告',state.mode)}${opt('false_positive','查误伤',state.mode)}</select>`,'ada-narrow')}
      ${field('采集时限（秒）',`<input id="ada-ttl" type="number" data-field="ttl" min="30" max="${state.cap?.limits?.observe_ttl_max||1800}" value="${state.ttl}" ${!writable()?'disabled':''}>`,'ada-narrow')}
      ${btn(state.sessions.length?'新建设备分析':'开始采集','start',!canStart||!state.deviceIp)}
    </form>${!state.cap?'<p class="ada-muted">采集能力和权限尚未确认。</p>':!writable()?'<p class="ada-muted">只读账号可查看记录；新建采集和修改报告需要操作权限。</p>':!canStart?`<p class="ada-notice">${esc(state.cap?.preparation_message||'正在确认采集能力')}</p>`:''}`;
  }
  function table(rows,history=false) {
    const selected=selection();
    return `<div class="dwrt-kit-table-scroll ada-table-scroll" id="${history?'ada-report-scroll':`ada-live-scroll-${state.group?esc(rows[0]?.group_key||rows[0]?.domain||'empty'):'all'}`}"><table class="dwrt-kit-table ada-table"><thead><tr><th>${history?'':`<input type="checkbox" data-ada-action="select-all" aria-label="选择当前页筛选结果" ${rows.length&&rows.every((r)=>selected.has(r.domain))?'checked':''}>`}</th><th>域名</th><th>DNS 查询</th><th>线索强度</th><th>实际观测</th><th>最近出现</th></tr></thead><tbody>${rows.map((d)=>`<tr id="${history?'hist':'live'}-${esc(d.id)}"><td>${history?'':`<input type="checkbox" data-ada-action="select-row" data-domain="${esc(d.domain)}" aria-label="选择 ${esc(d.domain)}" ${selected.has(d.domain)?'checked':''}>`}</td><td><button class="ada-domain" data-ada-action="evidence" data-domain="${esc(d.domain)}" ${history?'data-history="true"':''}>${esc(d.domain)}</button>${!history&&decisions().has(d.domain)?`<div class="ada-meta">草稿：${decisions().get(d.domain)==='allow'?'放行':'拦截'}</div>`:''}</td><td>${d.dns_count??'—'}</td><td>${esc(names[d.clue_level]||'未知')} · ${d.clue_score??'—'}</td><td>${d.blocked_observed?'DNS 零地址应答':'未记录阻断应答'}</td><td>${esc(when(d.last_seen))}</td></tr>`).join('')}</tbody></table></div>`;
  }
  function grouped(rows){const groups=new Map();for(const d of rows){const k=d.group_key||d.domain;if(!groups.has(k))groups.set(k,[]);groups.get(k).push(d);}return [...groups].map(([k,ds])=>`<details id="ada-group-${esc(k)}"><summary>${esc(k)} · 本页 ${ds.length} 个域名</summary>${btn('选择本组（当前页）','select-group',false,`data-group="${esc(k)}"`)}${table(ds)}</details>`).join('');}
  function evidence() {
    const d=state.evidenceHistory?state.report?.domains?.[state.evidence]:state.rows.find((d)=>d.domain===state.evidence);
    if(!d)return '<p class="ada-muted">选择一个域名，查看应答、归属和线索依据。</p>';
    const items=[['完整域名',d.domain],['证据来源','DNS 查询工作日志'],['客户端归属',d.attribution==='exact_source_ip'?'查询来源 IP 精确匹配':'未知'],['首次出现',when(d.first_seen)],['查询类型',(d.qtypes||[]).join('、')],['DNS 应答',(d.answers||[]).join('、')||'尚无可关联应答'],['CNAME 链',(d.cnames||[]).join(' → ')||'未观测到目标'],['应答状态',(d.response_codes||[]).join('、')||'日志未返回明确状态码'],['解析地址',(d.resolved_ips||[]).join('、')||'未观测'],['规则匹配',d.rule?`${d.rule.action==='allow'?'放行':'拦截'} · ${d.rule.match==='suffix'?'后缀':'精确'} ${d.rule.matched_domain} · ${d.rule.id}`:'规则 ID、provider 及父域匹配尚未确认'],['连接线索',d.has_connection_clue?'相同设备的地址或主机名线索关联（推断，共享地址不能证明具体域名连接）':'尚无对应连接线索'],['明细完整性',d.evidence_truncated?'部分应答因单域名容量上限未保留':'未报告明细截断'],['评分版本',d.score_version]];
    return `<h3>${esc(d.domain)}</h3><dl>${items.map(([k,v])=>`<dt>${esc(k)}</dt><dd>${esc(v||'未知')}</dd>`).join('')}</dl><strong>线索依据</strong><ul>${(d.clue_factors||[]).map((f)=>`<li>${f.delta>0?'+':''}${f.delta} · ${esc(f.detail||f.code)}</li>`).join('')||'<li>未发现明显线索，不代表绝对安全。</li>'}</ul><p class="ada-muted">DNS 查询与零地址应答不能证明广告展示、握手成功或 HTTPDNS 绕过。连接中的域名提示是推断，完整 IP 线索另列。</p>${btn('复制完整域名','copy-domain',false,`data-domain="${esc(d.domain)}"`)}`;
  }
  function visibleRows(){return state.rows.filter((d)=>(!state.q||`${d.domain} ${JSON.stringify(d.clue_factors)}`.toLowerCase().includes(state.q.toLowerCase()))&&(!state.level||d.clue_level===state.level)&&(!state.blocked||d.blocked_observed));}
  function timeline(rows){const bins=new Map();rows.forEach((r)=>{if(!r.first_seen)return;const t=Math.floor(r.first_seen/10)*10;if(!bins.has(t))bins.set(t,[]);bins.get(t).push(r.domain);});return `<details><summary>当前页首次出现的新域名</summary><div class="ada-timeline">${[...bins.entries()].sort((a,b)=>a[0]-b[0]).map(([t,ds])=>btn(`${new Date(t*1000).toLocaleTimeString('zh-CN')} · ${ds.length}`,'time',false,`data-time="${t}"`)).join('')||'<p class="ada-muted">尚无带时间的域名记录</p>'}</div></details>`;}
  function connections(s){
    const all=Object.values(s.connections||{});
    const domains=state.report===s?Object.values(s.domains||{}):state.rows;
    const known=new Set(domains.flatMap(d=>d.resolved_ips||[]));
    const rows=state.unmatchedConnections?all.filter(r=>!r.domain_hint&&!known.has(r.destination_ip)):all;
    return `<details class="ada-connections"><summary>连接与直连 IP 线索 · ${rows.length} 条</summary><label class="ada-meta"><input type="checkbox" data-field="unmatchedConnections" ${state.unmatchedConnections?'checked':''}> 只看尚无当前域名列表对应的连接</label><p class="ada-meta">该筛选不证明绕过 DNS；域名列表受当前分页和筛选影响。按来源 IP 的连接快照及已完成流记录；短连接可能未被快照捕获。未观测域名保持未知，UDP 443 只提供 IP 线索。</p>${rows.length?`<div class="dwrt-kit-table-scroll"><table class="dwrt-kit-table"><thead><tr><th>目标</th><th>协议</th><th>来源</th><th>域名线索</th><th>规则动作</th></tr></thead><tbody>${rows.map((r)=>`<tr><td>${esc(r.destination_ip)}:${r.destination_port}</td><td>${esc(r.protocol)}</td><td>${r.source==='conntrack_snapshot'?'连接快照':'已完成连接'}${r.present_at_start?' · 开始前已存在':''}</td><td>${esc(r.domain_hint||'未知')}${r.domain_hint?'（推断）':''}</td><td>${esc(r.policy_action||'未记录')} ${esc(r.policy_id||'')}</td></tr>`).join('')}</tbody></table></div>`:'<p>尚未采集到此设备的连接线索。</p>'}</details>`;
  }
  function historyDetails(s) {
    return `<p>结论更新于 ${when(s.conclusions_updated_at)}</p><ul>${(s.conclusions||[]).flatMap((c)=>c.rules||[]).map((r)=>`<li>${esc(r.domain)} · ${r.action==='allow'?'放行':'拦截'} · ${esc(r.id)} <a href="/app/#/policy-engine/aegisx">查看内容规则</a></li>`).join('')||'<li>尚未保存永久规则。</li>'}</ul><ol>${(s.trial_history||[]).map((h)=>`<li>${when(h.at)} · ${esc(describe(h.event))}${h.detail?.feedback?` · ${esc(describe(h.detail.feedback))}`:''}</li>`).join('')}</ol>`;
  }
  function trialPanel(s) {
    const t=s.trial,x=s.bisect;if(!t&&!x)return '';
    const enabled=sessionWritable()&&trialActive()&&(!x||x.state==='awaiting_feedback');
    const list=(a)=>(a||[]).map((r)=>`${esc(r.domain)}（${r.action==='allow'?'放行':'拦截'}）`).join('、')||'无';
    return `<section class="ada-trial" aria-label="当前试验"><h3>${x?`分轮排查 · 第 ${x.round} 轮`:'手动试验'}</h3><p>${esc(describe(t?.apply_state))} · 到期 ${when(t?.expires_at)}</p>${x?`<p>${esc(describe(x.state))}${x.final_retest?' · 单候选最终复测':''}；剩余 ${x.candidates?.length||0} 个候选</p><p>本轮保留：${list(x.holdout)}</p><p>已排除：${list(x.cleared)}</p>`:''}<p>实际作用集合：${list(t?.rules)}</p><div class="ada-actions">${btn(s.mode==='false_positive'?'功能恢复了':'广告消失了','feedback-effective',!enabled)}${btn(s.mode==='false_positive'?'仍然异常':'广告还在','feedback-ineffective',!enabled)}${btn('不确定，重试本轮','feedback-uncertain',!enabled)}${btn('回退上一轮','undo',!sessionWritable()||!x?.history?.length||['ended','expired','replaced_manually'].includes(x?.state))}${btn('撤回试验','revoke',!sessionWritable()||!trialActive())}</div><p class="ada-meta">反馈前请刷新目标设备内容并检查正常功能。缓存、广告轮播和多个原因可能使结果不一致；单条复测有效也不证明只有这一条原因。</p>${x?.state==='verified_candidate'?btn('将复测候选加入保存草稿','adopt',!sessionWritable()):''}${x?.state==='unlocated'?'<p class="ada-notice">当前候选未能稳定复现结果。可回退，或重新选组确认基线。</p>':''}</section>`;
  }
  function workbench() {
    const s=state.session,rows=visibleRows();
    return `<div class="ada-pane">${setup()}${state.sessions.length?field('设备会话',`<select id="ada-sessions" data-field="selected" ${state.busy?'disabled':''}>${state.sessions.map((x)=>opt(x.session_id,`${x.device_label} · ${modeName(x.mode)} · ${names[x.state]||x.state}`,state.selected)).join('')}</select>`):state.sessionsLoaded?'<p class="ada-empty">尚无分析记录。选好设备后开始采集，再在设备上复现广告或访问异常。</p>':'<p class="ada-empty">会话列表尚未读取。</p>'}
    ${s?`<div class="ada-status"><strong>${esc(s.device_label)} · ${esc(s.device_ip)}</strong><span>${esc(modeName(s.mode))} · ${esc(describe(s.state))}</span><span>${esc(describe(s.report_state))}</span><span>开始于 ${esc(when(s.started_at))}</span><span>到期 ${esc(when(s.expires_at))}</span></div>
      <div class="ada-actions">${btn('停止采集','stop',!sessionWritable()||!['capturing','degraded'].includes(s.state))}${btn('结束并撤回试验','end',!sessionWritable())}<span class="ada-meta">${trialActive()?`试验剩余 ${Math.max(0,Math.ceil(s.trial.expires_at-Date.now()/1000))} 秒`:'当前无生效中的临时试验'}</span></div>
      <div class="ada-status">${(s.sources||[]).map((x)=>`<span>${esc(sourceNames[x.id]||x.id)}：${esc(describe(x.state))}</span>`).join('')}</div>
      ${s.stop_reason?`<p class="ada-meta">停止原因：${esc(describe(s.stop_reason))}</p>`:''}${s.source_reason?`<p class="ada-notice">${esc(describe(s.source_reason))}</p>`:''}${s.truncated||state.obs?.truncated?`<p class="ada-notice">采集不完整：${esc(describe(s.coverage_reason||state.obs?.coverage_reason))}。丢弃 ${s.dropped??state.obs?.dropped??0} 条。</p>`:''}
      <div class="ada-workspace"><section class="dwrt-kit-table-wrap ada-panel"><div class="dwrt-kit-table-toolbar"><strong>域名证据</strong><span class="dwrt-kit-table-count">本页 ${rows.length} / 共 ${state.obs?.total??'—'} 条</span></div>
      <div class="ada-filters">${field('搜索域名或线索',`<input id="ada-search" data-field="q" value="${esc(state.q)}" type="search">`,'ada-search')}${field('线索等级',`<select id="ada-level" data-field="level">${opt('','全部',state.level)}${['none','low','suspicious','high'].map((v)=>opt(v,names[v],state.level)).join('')}</select>`,'ada-narrow')}<label class="ada-meta"><input type="checkbox" data-field="group" ${state.group?'checked':''}> 按注册域分组</label><label class="ada-meta"><input type="checkbox" data-field="blocked" ${state.blocked?'checked':''}> 仅有阻断应答</label><label class="ada-meta"><input type="checkbox" data-field="connection" ${state.connection?'checked':''}> 有连接线索（推断）</label><label class="ada-meta"><input type="checkbox" data-field="parent" ${state.parent?'checked':''}> 已知父域规则连带</label></div>
      ${rows.length?(state.group?grouped(rows):table(rows)):`<p class="ada-empty">${state.rows.length?'当前筛选无匹配域名。':'本会话尚无可关联 DNS 查询；请在目标设备复现，并确认 DNS 经过本机。'}</p>`}<div class="ada-actions">${btn('选择全部筛选结果','select-filter',!sessionWritable())}${btn('上一页','prev',state.offset===0)}${btn('下一页','next',state.offset+100>=(state.obs?.total||0))}<span class="ada-meta">每页 100 条；筛选覆盖整个会话，时间线显示当前页。</span></div>${timeline(rows)}</section><aside class="ada-evidence" aria-label="域名证据">${evidence()}</aside></div>
      <section class="ada-decisions"><h3>候选与试验</h3><div class="ada-actions">${btn('标记为拦截候选','mark-block',!sessionWritable()||!selection().size)}${btn('标记为放行候选','mark-allow',!sessionWritable()||!selection().size)}${btn('取消所选标记','unmark',!selection().size)}${btn('清除本会话草稿','clear',!decisions().size)}</div><p class="ada-meta">已选 ${selection().size} 个域名 · 草稿 ${decisions().size} 条。标记不会修改过滤规则。</p><div class="ada-filters">${field('试验时限（秒）',`<input id="ada-trial-ttl" data-field="trialTtl" type="number" min="30" max="900" value="${state.trialTtl}">`,'ada-narrow')}<label class="ada-meta"><input type="checkbox" data-field="baseline" ${state.baseline?'checked':''}> 已确认问题可重复出现</label></div><div class="ada-actions">${btn('临时拦截所选','trial-block',!canTrial('block')||!selection().size||selection().size>128)}${btn('临时放行所选','trial-allow',!canTrial('allow')||!selection().size||selection().size>128)}${btn('分轮排查','bisect',!canTrial('block')||!decisions().size||decisions().size>128||!state.baseline)}${btn('查看保存预览','preview',!sessionWritable()||!decisions().size||decisions().size>128)}</div><p class="ada-meta">每次最多 128 个候选。试验只作用于当前设备的 DHCP IPv4 来源经本机 DNS 的查询，含 A/AAAA。IPv6 来源试验尚未提供；动作由拦截/放行标记决定。</p>${trialPanel(s)}<label class="ada-meta"><input type="checkbox" data-field="scopeAll" ${state.scopeAll?'checked':''}> 永久规则改为全网范围（保存时单独确认）</label><p class="ada-notice">${esc(state.cap?.actions?.message||describe(state.cap?.actions?.reason)||'试验能力尚未确认')}</p>${state.preview?`<div><strong>保存预览 · 尚未保存</strong><ul>${state.preview.rules.map((r)=>`<li>${esc(r.domain)} · ${r.action==='allow'?'放行':'拦截'} · 精确域名 · ${esc(r.provider)}<br><span class="ada-meta">${esc(r.operation||'')} · ${esc(r.id||'')} ${esc(describe(r.conflict))}</span></li>`).join('')}</ul><p>范围：${state.preview.scope?.type==='all'?'全网':`当前设备 ${esc(s.device_id||s.device_ip)}`} · 规则版本 ${state.preview.provider_revision??'未知'}</p>${(state.preview.conflicts||[]).map((c)=>`<p class="ada-notice">${esc(c.domain)}：${esc(describe(c.reason))} · ${esc(c.rule_id)}</p>`).join('')}${btn('保存为永久规则','commit',!state.preview.can_commit)}</div>`:''}</section>
      ${connections(s)}`:''}</div>`;
  }
  function historyPane() {
    const r=state.report;return `<div class="ada-pane"><div class="ada-filters">${field('筛选设备 IP',`<input id="ada-report-ip" data-field="reportIp" value="${esc(state.reportIp)}" placeholder="全部设备">`)}${field('分析模式',`<select id="ada-report-mode" data-field="reportMode">${opt('','全部',state.reportMode)}${opt('find_ads','找广告',state.reportMode)}${opt('false_positive','查误伤',state.reportMode)}</select>`,'ada-narrow')}${btn('查询报告','reports')}</div><p class="ada-muted">每设备保留 ${state.cap?.limits?.report_retention_per_device??'—'} 份，总计最多 ${state.cap?.limits?.report_list_max??'—'} 份。删除报告不删除规则。</p>
    <div class="ada-history-list">${state.reports.map((r)=>`<article class="ada-report-row"><div><strong>${esc(r.label||r.device_label)}</strong><div class="ada-meta">${esc(r.device_ip)} · ${modeName(r.mode)} · ${when(r.captured_at)} · ${r.total_domains} 个域名</div></div>${btn('查看','report',false,`data-id="${esc(r.id)}"`)}</article>`).join('')||(state.reportsLoaded?'<p class="ada-empty">当前条件下没有报告。</p>':'<p class="ada-empty">报告列表尚未读取。</p>')}</div><div class="ada-actions">${btn('上一页','reports-prev',state.reportOffset===0)}${btn('下一页','reports-next',state.reportOffset+20>=state.reportTotal)}</div>
    ${r?`<section class="ada-history-detail"><div class="ada-toolbar"><h3>${esc(r.device_label)} · ${modeName(r.mode)}</h3>${btn('关闭详情','close-report')}</div><p class="ada-meta">采集结束于 ${when(r.captured_at)} · ${esc(describe(r.stop_reason))}${r.truncated?` · 记录不完整：${esc(describe(r.coverage_reason))}`:''}</p>${field('报告备注',`<input id="ada-report-label" data-field="reportLabel" maxlength="160" value="${esc(state.reportLabel)}" ${!r.can_operate||state.busy?'readonly':''}>`)}<div class="ada-actions">${btn('保存备注','save-label',!r.can_operate||state.reportLabel===r.label)}${btn('删除这份报告','delete-report',!r.can_operate)}${btn('用这些候选新建分析','reuse',!writable())}</div><p class="ada-muted">历史复用会新建相同 IP、相同模式的会话；不会再次应用旧规则。</p>${table(Object.values(r.domains||{}).slice(state.reportDomainOffset,state.reportDomainOffset+100),true)}<div class="ada-actions">${btn('上一页域名','report-domains-prev',state.reportDomainOffset===0)}${btn('下一页域名','report-domains-next',state.reportDomainOffset+100>=Object.keys(r.domains||{}).length)}<span class="ada-meta">共 ${Object.keys(r.domains||{}).length} 条，当前第 ${Math.floor(state.reportDomainOffset/100)+1} 页</span></div><aside class="ada-evidence">${state.evidenceHistory?evidence():''}</aside><details><summary>来源与结论</summary><p>${(r.sources||[]).map((x)=>`${esc(sourceNames[x.id]||x.id)}：${esc(describe(x.state))}`).join('；')}</p>${connections(r)}${historyDetails(r)}</details></section>`:''}</div>`;
  }
  function render() {
    if(!state.live||confirmation)return;
    const html=`<div class="ada-app ${desktop?'':'dwrt-kit-page-surface dwrt-kit-glass-surface'}">${desktop?tabs():''}<main class="ada-main">${!desktop?tabs():''}<p id="ada-error" class="ada-notice" role="alert" ${!state.error?'hidden':''}>${esc(state.error)}${state.lastSuccess?`；最后成功更新于 ${when(state.lastSuccess)}`:''}</p><p class="ada-notice" role="status" ${!state.notice?'hidden':''}>${esc(state.notice)}</p>${state.loading?'<p class="ada-muted">正在读取分析能力和记录…</p>':''}${state.tab==='history'?historyPane():workbench()}<span class="ada-meta">${state.busy?'正在处理请求…':state.lastSuccess?`最近读取 ${when(state.lastSuccess)}`:''}</span></main></div>`;
    const draw=(target)=>{target.innerHTML=html;};
    if(ui.preserveInteractionState)ui.preserveInteractionState(root,draw);else draw(root);
    if(!desktop)root.querySelectorAll('p,h3,summary,.ada-meta,.ada-status > *, .ada-field > span,.ada-field input,.ada-field select,.ada-evidence dt,.ada-evidence dd,.ada-report-row strong,[data-ada-action]').forEach((node)=>node.setAttribute('data-adaptive-sample',''));
    ui.mountAll?.(root);const sessionSelect=root.querySelector("#ada-sessions");if(sessionSelect)sessionSelect.value=state.selected;
  }
  async function loadSession(id=state.selected) {
    if(!id)return;const seq=++seenSeq;
    const [s,o]=await Promise.all([request(`sessions/${encodeURIComponent(id)}`),request(`sessions/${encodeURIComponent(id)}/observations?${new URLSearchParams({limit:'100',offset:String(state.offset),q:state.q,level:state.level,blocked:state.blocked?'1':'',connection:state.connection?'1':'',parent:state.parent?'1':''})}`)]);
    if(!state.live||seq!==seenSeq||state.selected!==id)return;
    state.session=s;state.obs=o;state.rows=o.observations||[];
    if(s.candidates?.length&&!state.drafts.has(id))state.drafts.set(id,new Map(s.candidates.map((d)=>[d,s.mode==='false_positive'?'allow':'block'])));
  }
  async function loadReports() {const q=new URLSearchParams({limit:'20',offset:String(state.reportOffset),device_ip:state.reportIp,mode:state.reportMode});const r=await request(`reports?${q}`);if(!state.live)return;state.reports=r.reports||[];state.reportTotal=r.total||0;state.reportsLoaded=true;}
  async function refresh() {
    if(inflight||state.busy||confirmation||!visible())return;inflight=true;const epoch=writeEpoch;
    try {
      state.cap=await request('capabilities');const list=await request('sessions');if(!state.live||epoch!==writeEpoch)return;state.sessions=list.sessions||[];state.sessionsLoaded=true;
      if(!state.selected||!state.sessions.some((s)=>s.session_id===state.selected)){state.selected=state.sessions[0]?.session_id||'';state.offset=0;state.session=null;state.rows=[];}
      if(state.tab==='history')await loadReports();else await loadSession();if(epoch!==writeEpoch)return;state.error='';state.lastSuccess=Date.now()/1000;
    }catch(e){if(e.name!=='AbortError'&&epoch===writeEpoch)state.error=errorText(e);}finally{inflight=false;state.loading=false;render();}
  }
  async function confirm(title,description) {
    if(!ui.confirmationMarkup)return window.confirm(`${title}\n${description}`);
    return new Promise((resolve)=>{const holder=document.createElement('div');holder.innerHTML=ui.confirmationMarkup({title,description,tone:'warning'});root.append(holder);ui.mountAll?.(holder);const focus=document.activeElement;
      const finish=(value)=>{ui.unmount?.(holder);holder.remove();confirmation=null;focus?.focus();resolve(value);};confirmation=()=>finish(false);
      holder.addEventListener('click',(e)=>{if(e.target.closest('[data-dwrt-confirm-accept]'))finish(true);if(e.target.closest('[data-dwrt-confirm-cancel]'))finish(false);});holder.querySelector('[data-dwrt-confirm-cancel]')?.focus();
    });
  }
  async function write(path,method,body) {
    const key=JSON.stringify([path,method,body]);
    if(!pendingWrites.has(key))pendingWrites.set(key,freshId());
    try {const r=await request(path,method,{...body,request_id:pendingWrites.get(key)});pendingWrites.delete(key);return r;}
    catch(e){if(e.status>0&&e.status<500)pendingWrites.delete(key);throw e;}
  }
  async function act(action,el) {
    if(state.busy)return;
    if(action==='tab'){state.tab=el.dataset.tab;state.evidenceHistory=false;render();await refresh();return;}
    if(action==='refresh'){await refresh();return;}
    if(action==='copy-domain'){try{await navigator.clipboard.writeText(el.dataset.domain);state.notice='已复制完整域名。';}catch(_){state.notice='浏览器未允许复制，请从证据区选择完整域名。';}render();return;}
    if(action==='evidence'){state.evidence=el.dataset.domain;state.evidenceHistory=el.dataset.history==='true';render();return;}
    if(action==='select-group'){state.rows.filter((d)=>(d.group_key||d.domain)===el.dataset.group).forEach((d)=>selection().add(d.domain));render();return;}
    if(action==='select-row'){el.checked?selection().add(el.dataset.domain):selection().delete(el.dataset.domain);render();return;}
    if(action==='adopt'){for(const r of state.session?.bisect?.culprits||[])decisions().set(r.domain,r.action);state.preview=null;render();return;}
    if(action==='select-all'){visibleRows().forEach((r)=>el.checked?selection().add(r.domain):selection().delete(r.domain));render();return;}
    if(action==='time'){const time=Number(el.dataset.time);state.rows.filter((r)=>Math.floor(r.first_seen/10)*10===time).forEach((r)=>selection().add(r.domain));render();return;}
    if(['mark-block','mark-allow','unmark','clear'].includes(action)){if(action.startsWith('mark')&&!sessionWritable())return;for(const d of selection()){if(action==='unmark')decisions().delete(d);else if(action==='mark-block'||action==='mark-allow')decisions().set(d,action==='mark-allow'?'allow':'block');}if(action==='clear')decisions().clear();state.preview=null;render();return;}
    if(action==='report-domains-prev'||action==='report-domains-next'){state.reportDomainOffset=Math.max(0,state.reportDomainOffset+(action==='report-domains-next'?100:-100));render();return;}
    if(action==='close-report'){if(state.reportLabel!==state.report?.label&&!await confirm('放弃备注修改？','仅关闭当前报告详情。'))return;state.report=null;render();return;}
    state.busy=true;writeEpoch++;seenSeq++;state.notice='';render();
    try {
      if(action==='select-filter'){
        const limit=state.cap?.limits?.observations_page_max||500;let offset=0,total=1;
        while(offset<total){const r=await request(`sessions/${state.selected}/observations?${new URLSearchParams({limit:String(limit),offset:String(offset),q:state.q,level:state.level,blocked:state.blocked?'1':'',connection:state.connection?'1':'',parent:state.parent?'1':''})}`);for(const d of r.observations||[])selection().add(d.domain);total=r.total;offset+=limit;}state.notice=`已选择 ${selection().size} 条；试验或保存一次最多 128 条。`;
      }else if(action==='start'){
        if(!writable())return;
        const r=await write('sessions','POST',{device_ip:state.deviceIp,device_id:state.target,mode:state.mode,observe_ttl:Number(state.ttl)});state.selected=r.session_id;state.offset=0;
      }else if(action==='stop'||action==='end'){
        if(!sessionWritable())return;const r=await write(`sessions/${state.selected}/${action}`,'POST',{expected_revision:state.session.revision});state.notice=r.report_saved?'采集已停止，报告已保存。':'操作已返回，请检查报告状态。';
      }else if(action==='preview'){
        state.preview=await write(`sessions/${state.selected}/conclusions/preview`,'POST',{expected_revision:state.session.revision,scope:scope(),confirm_global:state.scopeAll,rules:draftRules()});
      }else if(['trial-block','trial-allow','bisect','revoke','undo','commit'].includes(action)||action.startsWith('feedback-')){
        if(!sessionWritable())return;
        const sid=state.selected,s=state.session;
        if(action==='commit'){
          if(!state.preview?.can_commit)return;
          if(!await confirm(state.preview.scope?.type==='all'?'保存全网规则？':'保存当前设备规则？',`将明确保存 ${state.preview.rules.length} 条精确域名规则；${state.preview.scope?.type==='all'?'影响所有设备':'仅影响当前设备'}。`))return;
          const saved=await write(`sessions/${sid}/conclusions/commit`,'POST',{expected_revision:s.revision,provider_revision:state.preview.provider_revision,scope:state.preview.scope,confirm_global:state.preview.scope?.type==='all',rules:state.preview.rules.map(({domain,action,match})=>({domain,action,match}))});
          for(const rule of saved.rules||[]){if(decisions().get(rule.domain)===rule.action)decisions().delete(rule.domain);}
          state.preview=null;state.notice=`已保存并应用 ${saved.rules?.length||0} 条规则，可在 AegisX 内容规则中查看。`;
        }else if(action==='revoke'){
          await write(`sessions/${sid}/trial`,'DELETE',{expected_revision:s.revision});state.notice='试验已撤回。';
        }else{
          const cap=await request('capabilities');
          let payload={expected_revision:s.revision,provider_revision:cap.provider?.provider_revision,scope:{type:'device',device_id:s.device_id},ttl_seconds:Number(state.trialTtl)};
          // Obtain the provider revision from a read-only preview of this round.
          const currentRules=action==='bisect'?draftRules():action.startsWith('trial-')?[...selection()].map((domain)=>({domain,match:'exact',action:action==='trial-allow'?'allow':'block'})):s.trial.rules;
          const pv=await write(`sessions/${sid}/conclusions/preview`,'POST',{expected_revision:s.revision,scope:payload.scope,rules:currentRules});payload.provider_revision=pv.provider_revision;
          if(!pv.can_commit)throw new Error((pv.conflicts||[]).map((c)=>`${c.domain}：${describe(c.reason)}`).join('；')||'该组存在规则冲突');
          let path='trial';
          if(action==='bisect'){path='bisect';payload={...payload,rules:currentRules,baseline_confirmed:state.baseline};}
          else if(action==='undo'){path='bisect/undo';payload={...payload,trial_id:s.trial.id,round_id:s.bisect.round_id};}
          else if(action.startsWith('feedback-')){path=s.bisect?.state==='awaiting_feedback'?'bisect/feedback':'trial/feedback';payload={...payload,trial_id:s.trial.id,round_id:s.bisect?.round_id,feedback:action.slice(9)};}
          else payload.rules=currentRules;
          await write(`sessions/${sid}/${path}`,'POST',payload);state.notice='操作已应用，正在读取当前试验。';
        }
      }else if(action==='prev'||action==='next'){state.offset=Math.max(0,state.offset+(action==='next'?100:-100));}
      else if(action==='reports'){state.reportOffset=0;await loadReports();}
      else if(action==='reports-prev'||action==='reports-next'){state.reportOffset=Math.max(0,state.reportOffset+(action==='reports-next'?20:-20));await loadReports();}
      else if(action==='report'){if(state.report&&state.reportLabel!==state.report.label&&!await confirm('放弃备注修改？','打开另一份报告会丢弃当前未保存的备注。'))return;state.report=await request(`reports/${el.dataset.id}`);state.reportLabel=state.report.label||'';state.reportDomainOffset=0;state.evidenceHistory=false;}
      else if(action==='save-label'){
        const r=state.report;await write(`reports/${r.id}`,'PATCH',{expected_revision:r.report_revision,label:state.reportLabel});const saved=await request(`reports/${r.id}`);if(saved.label!==state.reportLabel)throw new Error('备注回读不一致，草稿仍保留');state.report=saved;state.notice='备注已保存并回读确认。';
      }else if(action==='delete-report'){
        const r=state.report;if(!await confirm('删除这份报告？',`${r.device_ip} · ${modeName(r.mode)}。只删除报告，不删除过滤规则。`))return;await write(`reports/${r.id}`,'DELETE',{expected_revision:r.report_revision});state.report=null;state.notice='报告已删除。';await loadReports();
      }else if(action==='reuse'){
        const r=state.report;if(!await confirm('用历史候选新建分析？',`目标 ${r.device_ip}，模式「${modeName(r.mode)}」。新会话仅采集和标记候选，不应用规则。`))return;
        const candidates=Object.values(r.domains||{}).filter((d)=>r.mode==='false_positive'?d.blocked_observed:d.clue_score>0).map((d)=>d.domain).slice(0,128);
        const created=await write('sessions','POST',{device_ip:r.device_ip,device_id:r.device_id,mode:r.mode,observe_ttl:state.cap?.limits?.observe_ttl_default||600,reuse_report_id:r.id,candidates});state.selected=created.session_id;state.offset=0;state.tab='workbench';state.notice=`新会话已创建，带入 ${created.candidates?.length||0} 个候选；未应用过滤规则。`;
      }
      if(state.selected&&state.tab==='workbench')await loadSession();
      state.error='';
    }catch(e){state.error=errorText(e);}finally{state.busy=false;render();if(!state.error)await refresh();}
  }
  const onClick=(e)=>{const el=e.target.closest('[data-ada-action]');if(!el||el.disabled)return;if(el.type!=='checkbox')e.preventDefault();void act(el.dataset.adaAction,el);};
  const onInput=(e)=>{const el=e.target.closest('[data-field]');if(!el)return;const key=el.dataset.field;
    if(key==='selected'){state.selected=el.value;state.offset=0;state.session=null;state.rows=[];state.preview=null;state.evidence='';render();void loadSession().then(render).catch((err)=>{state.error=errorText(err);render();});return;}
    state[key]=el.type==='checkbox'?el.checked:el.value;
    if(key==='scopeAll')state.preview=null;
    if(key==='target'){state.deviceIp=state.clients.find((c)=>c.mac===el.value)?.ip||'';}
    if(['q','level','blocked','connection','parent'].includes(key)){
      state.offset=0;seenSeq++;clearTimeout(filterTimer);
      filterTimer=setTimeout(()=>{void loadSession().then(render).catch((err)=>{state.error=errorText(err);render();});},key==='q'?250:0);
    }
    render();
  };
  const beforeUnload=(e)=>{if(dirty()||state.busy||trialActive()){e.preventDefault();e.returnValue='';}};
  const onKey=(e)=>{if(e.key==='Escape'&&confirmation){e.preventDefault();confirmation();}};
  function visible(){if(document.hidden)return false;try{if(window.frameElement&&parent.DWRT_DESKTOP_HOST){const win=window.frameElement.closest('[data-app-id],.desktop-window');if(win?.hidden||win?.getAttribute('aria-hidden')==='true')return false;}}catch(_){}return true;}
  let priorHash=location.hash;
  const hashChange=(e)=>{if(dirty()&&!window.confirm('有未保存的广告分析草稿，放弃并离开？')){history.replaceState(null,'',priorHash);e.stopImmediatePropagation();}else priorHash=location.hash;};
  const onSubmit=(e)=>e.preventDefault();
  root.classList.add('ada-host');root.addEventListener('click',onClick);root.addEventListener('input',onInput);root.addEventListener('change',onInput);root.addEventListener('keydown',onKey);root.addEventListener('submit',onSubmit);window.addEventListener('beforeunload',beforeUnload);window.addEventListener('hashchange',hashChange,true);
  render();void refresh();void request('/api/v1/clients?limit=200').then((r)=>{state.clients=(r.clients||r.items||[]).filter((c)=>c.ip&&c.mac);render();}).catch(()=>{state.clients=[];});poll=setInterval(refresh,5000);
  const visibility=()=>{if(visible())void refresh();};document.addEventListener('visibilitychange',visibility);
  const hostVisibility=(e)=>{if(e.source===parent&&e.origin===location.origin&&e.data?.type==='dwrt-app-visibility'&&e.data.visible)visibility();};window.addEventListener('message',hostVisibility);
  async function beforeClose(){
    if(state.busy)return false;
    let trials;
    try {const list=await request('sessions');trials=(list.sessions||[]).filter(s=>s.can_operate&&s.trial?.apply_state==='applied'&&s.trial.expires_at>Date.now()/1000);}
    catch(e){state.error=errorText(e);render();return false;}
    if(trials.length){
      const end=await confirm('关闭前结束试验？',`你有 ${trials.length} 个设备试验仍在生效。确认会结束并撤回这些试验；取消后可选择保留租约。`);
      if(end){
        state.busy=true;writeEpoch++;seenSeq++;
        try {for(const s of trials)await write(`sessions/${s.session_id}/end`,'POST',{expected_revision:s.revision});}
        catch(e){state.error=errorText(e);return false;}
        finally {state.busy=false;render();}
      }else if(!await confirm('按剩余租约继续？','关闭窗口后试验继续，到期由后端撤回；取消则留在当前页面。'))return false;
    }
    return !dirty()||await confirm('放弃未保存草稿并关闭？','已保存的会话和报告会保留。');
  }
  window.adAnalyzer={beforeClose};
  return {refresh,beforeClose,unmount(){state.live=false;seenSeq++;clearInterval(poll);clearTimeout(filterTimer);requests.forEach((r)=>r.abort());confirmation?.();root.removeEventListener('click',onClick);root.removeEventListener('input',onInput);root.removeEventListener('change',onInput);root.removeEventListener('keydown',onKey);root.removeEventListener('submit',onSubmit);window.removeEventListener('beforeunload',beforeUnload);window.removeEventListener('hashchange',hashChange,true);document.removeEventListener('visibilitychange',visibility);window.removeEventListener('message',hostVisibility);ui.unmount?.(root);root.replaceChildren();root.classList.remove('ada-host');}};
}
export default {mount,VERSION};
