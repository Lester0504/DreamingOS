const API = '/api/v1/community/';
export const messageId = () => 'msg-' + (crypto.randomUUID?.() || Date.now().toString(36) + Math.random().toString(36).slice(2));

// Created lazily in the desktop host, so an unopened registration iframe never logs in.
export function createCommunityClient() {
  const listeners = new Set();
  const state = {caps:null,session:null,status:'idle',error:'',messages:new Map(),pending:new Map(),whispers:[],members:[],online:null,cursor:'0',hasMore:false,gap:false,unread:0,prefs:{background:false,badge:true,sound:'off'}};
  let socket, timer, starting, stopped=true, generation=0, retries=0, connection='', membersAt=0;
  const emit = () => {
    state.unread=[...state.messages.values()].filter(m=>m.user_id!==state.session?.user_id && Number(m.cursor)>Number(state.session?.read_cursor||0)).length;
    for(const listener of listeners)listener(state);
    window.dispatchEvent(new CustomEvent('dwrt-community-state',{detail:{unread:state.prefs.badge?state.unread:0,status:state.status}}));
  };
  async function api(path,method='GET',body) {
    const response=await (window.DWRT_REQUEST?.fetch || window.fetch.bind(window))(API+path,{method,credentials:'same-origin',cache:'no-store',headers:{Accept:'application/json',...(body?{'Content-Type':'application/json'}:{})},...(body?{body:JSON.stringify(body)}:{})});
    let result;try{result=await response.json();}catch{throw Object.assign(Error('社区服务返回无效内容'),{status:response.status});}
    if(!response.ok||result.ok===false)throw Object.assign(Error(result.error?.message||result.message||`社区请求失败（${response.status}）`),{status:response.status,code:result.error?.code||result.error_code});
    return result.data;
  }
  function merge(items) {for(const item of items||[]){state.messages.set(item.message_id,item);if(Number(item.cursor)>Number(state.cursor))state.cursor=item.cursor;state.pending.delete(item.client_message_id);}}
  function stop() {stopped=true;starting=null;generation++;clearTimeout(timer);if(socket){socket.onclose=null;socket.close();socket=null;}connection='';state.status='disconnected';emit();}
  function reset() {stop();state.session=null;state.routeDraft=null;state.messages.clear();state.pending.clear();state.whispers=[];state.members=[];state.online=null;state.cursor='0';state.unread=0;emit();}
  function failure(error) {state.error=error.message;state.status=error.status===401?'login_required':error.status===403?'restricted':'disconnected';if([401,403].includes(error.status)){stopped=true;clearTimeout(timer);}emit();}
  async function refreshMembers() {let after='',items=[],page;do{page=await api('members'+(after?'?after='+encodeURIComponent(after):''));items.push(...page.items);after=page.items.at(-1)?.user_id||'';}while(page.has_more&&after&&items.length<500);state.members=items;state.online=page.online_count;membersAt=Date.now();}
  async function connect() {
    if(stopped||socket)return;const gen=generation;
    try {
      const ticket=await api('connection-ticket','POST',{});if(stopped||gen!==generation)return;
      const url=new URL(API+'ws',location.href);url.protocol=location.protocol==='https:'?'wss:':'ws:';url.searchParams.set('ticket',ticket.ticket);
      const ws=new WebSocket(url);socket=ws;state.status='connecting';emit();
      ws.onmessage=event=>{if(gen!==generation)return;let data;try{data=JSON.parse(event.data);}catch{return;}
        if(data.type==='connected'){connection=data.connection_id;ws.send(JSON.stringify({type:'resume',after:state.cursor}));state.status='connected';state.error='';retries=0;emit();}
        if(data.type==='events'){
          const fresh=(data.items||[]).filter(m=>!state.messages.has(m.message_id)&&m.user_id!==state.session?.user_id);
          merge(data.items);state.session=data.session;state.online=data.online_count;state.gap=data.gap===true;state.whispers.push(...(data.events||[]));state.whispers=state.whispers.slice(-100);emit();
          if(fresh.length)window.dispatchEvent(new CustomEvent('dwrt-community-message',{detail:{count:fresh.length}}));
          if(Date.now()-membersAt>15000)refreshMembers().then(emit).catch(e=>{state.error=e.message;emit();});
        }
        if(data.type==='connection.error')failure(Object.assign(Error(data.error?.message||'社区连接已中断'),{status:['banned','muted','community_session_revoked','community_session_expired'].includes(data.error?.code)?403:503}));
      };
      ws.onclose=event=>{if(gen!==generation)return;socket=null;connection='';if(event.code===4003||event.code===4001){stopped=true;state.status='login_required';state.error ||= '会话已结束，请重新登录';}else if(!stopped){state.status='disconnected';timer=setTimeout(connect,Math.min(30000,1000*2**Math.min(retries++,5)));}emit();};
      ws.onerror=()=>{state.error='社区连接暂不可用，正在重连';emit();};
    } catch(error){if(gen!==generation)return;failure(error);if(!stopped)timer=setTimeout(connect,Math.min(30000,1000*2**Math.min(retries++,5)));}
  }
  async function start() {
    if(starting)return starting;if(!stopped&&state.session)return;
    stopped=false;const gen=++generation;
    starting=(async()=>{try{
      state.status='loading';state.caps=await api('capabilities');if(gen!==generation)return;
      if(!state.caps.configured){stopped=true;state.status='unconfigured';state.error=state.caps.reason;emit();return;}
      try{state.prefs={...state.prefs,...JSON.parse(localStorage.getItem('dwrt.community.preferences:'+state.caps.local_subject)||'{}')};}catch{}
      const session=await api('session');if(gen!==generation)return;
      if(state.session&&state.session.user_id!==session.user_id){state.routeDraft=null;state.messages.clear();state.pending.clear();state.whispers=[];state.cursor='0';}
      state.session=session;
      if(state.cursor!=='0'){
        let page;do{page=await api('messages?after='+state.cursor);if(gen!==generation)return;merge(page.items);state.gap=page.gap===true;}while(page.has_more&&page.items.length);
      }else{const page=await api('messages');if(gen!==generation)return;merge(page.items);state.hasMore=page.has_more;state.gap=page.gap===true;}
      await refreshMembers();if(gen!==generation)return;emit();await connect();
    }catch(error){if(gen===generation){stopped=true;failure(error);}}finally{if(gen===generation)starting=null;}})();return starting;
  }
  async function older() {const first=[...state.messages.values()].sort((a,b)=>Number(a.cursor)-Number(b.cursor))[0];if(!first)return;const page=await api('messages?before='+first.cursor);merge(page.items);state.hasMore=page.has_more;emit();}
  async function send(draft,retryId) {
    if(state.status!=='connected')throw Error('连接恢复后再发送，内容已保留');
    if(state.session?.permissions.send!==true)throw Error('当前社区账号不能发言');
    const id=retryId||messageId(),existing=state.pending.get(id),entry=existing||{id,draft:{...draft},status:'sending'};entry.status='sending';entry.error='';state.pending.set(id,entry);emit();
    try {
      const p=entry.draft;
      if(p.target_user_id){if(p.image||p.attachment_id)throw Error('悄悄话仅支持文字，图片未发送');const ack=await api('whisper','POST',{connection_id:connection,client_message_id:id,target_user_id:p.target_user_id,text:p.text});state.pending.delete(id);emit();return ack;}
      if(p.image&&!p.attachment_id){const attachment=await api('attachments','POST',p.image);p.attachment_id=attachment.attachment_id;}
      const result=await api('messages','POST',{client_message_id:id,kind:p.attachment_id?'image':'text',text:p.text||'',attachment_id:p.attachment_id||'',mentions:p.mentions||[]});merge([result]);state.pending.delete(id);emit();return result;
    }catch(error){entry.status='failed';entry.error=error.message;entry.canEdit=error.status>=400&&error.status<500&&error.status!==408;emit();throw error;}
  }
  async function read(cursor) {if(!state.caps?.can_login||!state.session||Number(cursor)<=Number(state.session.read_cursor))return;const result=await api('read','POST',{cursor});state.session.read_cursor=result.cursor;emit();}
  function preferences(patch){Object.assign(state.prefs,patch);if(state.caps?.local_subject)localStorage.setItem('dwrt.community.preferences:'+state.caps.local_subject,JSON.stringify(state.prefs));if(!listeners.size&&!state.prefs.background)stop();emit();}
  return {state,api,start,stop,older,send,read,preferences,refreshMembers,
    editRejected(id){const entry=state.pending.get(id);if(!entry?.canEdit)return null;state.pending.delete(id);emit();return entry.draft;},
    subscribe(listener){listeners.add(listener);listener(state);return()=>{listeners.delete(listener);if(!listeners.size&&!state.prefs.background)stop();};},
    async logout(){await api('session','DELETE');reset();},
    async relogin(){if(state.session){await api('session','DELETE');reset();}return api('session','POST',{});},
    async completeLogin(){const data=await api('session/complete','POST',{});if(!data.pending){reset();await start();}return data;}
  };
}
let client;
export async function getCommunityClient() {
  try{if(top!==window&&top.DWRT_COMMUNITY_PROVIDER)return top.DWRT_COMMUNITY_PROVIDER();}catch{}
  return client ||= createCommunityClient();
}
