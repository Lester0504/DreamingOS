// Container-only client of the shared terminal session service.
const BASE = '/api/v1/container_service/lxc/terminal';
const VERSION = '20261006-lxc-05';
let assetsPromise;
const reasons = {
  lxc_command_missing:'缺少 lxc-attach、lxc-info 或 lxc-config。',
  lxc_container_not_running:'容器已停止、冻结或正在重启，请恢复运行后连接。',
  container_identity_changed:'目标容器已替换或不存在，请刷新列表后再连接。',
  lxc_container_not_found:'此容器已不存在，请刷新列表。',
  lxc_container_unreadable:'无法读取容器目录，请检查挂载与权限。',
  lxc_path_invalid:'当前 LXC 目录无效或配置了多个路径。',
  lxc_namespace_unavailable:'无法确认容器的独立进程空间。',
  lxc_attach_cleanup_unavailable:'当前内核不支持清理受控终端会话。',
  lxc_attach_identity_unconfirmed:'无法确认终端属于选中的容器。',
  lxc_shell_unavailable:'容器内没有所选 shell，请选择另一种 shell。',
  lxc_shell_not_executable:'容器内所选 shell 不可执行，请检查权限。',
  lxc_attach_failed:'LXC 附加失败，请检查容器运行日志。',
  lxc_attach_cleanup_failed:'未确认容器终端进程已结束，请检查此容器。',
  terminal_runtime_unavailable:'终端运行服务尚未安装或启动。',
  authorization_lease_expired:'会话授权已过期，请重新连接。',
  channel_closed:'交互连接已关闭。', remote_closed:'容器或 shell 已结束会话。',
  user_disconnected:'已断开此容器终端。', idle_timeout:'会话空闲超时。',
  owner_or_admin_required:'当前账号没有终端权限，需要设备所有者或管理员。',
};
export const terminalReason=reason=>reasons[reason]||reason||'当前环境无法连接容器终端。';
async function assets() {
  if (!document.querySelector('[data-lxc-xterm-css]')) {
    const link=document.createElement('link');link.rel='stylesheet';link.href='/static/vendor/terminal/xterm.css';link.dataset.lxcXtermCss='';document.head.append(link);
  }
  return assetsPromise ||= (async()=>{
    for (const [name,global] of [['xterm','Terminal'],['addon-fit','FitAddon']]) {
      if(window[global])continue;
      await new Promise((resolve,reject)=>{const tag=document.createElement('script');tag.src=`/static/vendor/terminal/${name}.js?v=${VERSION}`;tag.onload=resolve;tag.onerror=()=>reject(new Error('终端组件加载失败'));document.head.append(tag);});
    }
  })().catch(error=>{assetsPromise=null;throw error;});
}

export function mountTerminal({element,containerId,identity,workspace,request}) {
  const pane=element.querySelector('[data-container-terminal]');
  const note=element.querySelector('[data-terminal-state]');
  const connectButton=element.querySelector('[data-terminal-connect]');
  const disconnectButton=element.querySelector('[data-terminal-disconnect]');
  const select=element.querySelector('[data-terminal-shell]');
  let active=true,connecting=false,session=null,ws=null,term=null,fit=null,frame=0;
  const ended=()=>!session||['failed','closed','disconnected'].includes(session.state);
  function show(message) {
    note.textContent=message;
    connectButton.disabled=connecting||!ended();select.disabled=connectButton.disabled;
    disconnectButton.disabled=ended();
  }
  const send=value=>{if(ws?.readyState===WebSocket.OPEN)ws.send(JSON.stringify(value));};
  function palette() {
    // Solid terminal cells use semantic surface/text tokens; the surrounding Sheet owns glass.
    const style=getComputedStyle(document.documentElement);
    const foreground=style.getPropertyValue('--dwrt-ink').trim();
    const background=style.getPropertyValue('--color-surface-solid').trim();
    return {foreground,background,cursor:style.getPropertyValue('--color-accent').trim(),black:foreground,white:foreground,brightBlack:foreground,brightWhite:foreground};
  }
  function layout() {
    cancelAnimationFrame(frame);
    frame=requestAnimationFrame(()=>{if(!active||!term||!pane.clientWidth||!pane.clientHeight)return;term.options.theme=palette();fit.fit();if(session?.state==='ready')send({type:'resize',cols:term.cols,rows:term.rows});});
  }
  async function disconnect() {
    const previous=session;ws?.close();ws=null;
    if(previous&&!['failed','closed','disconnected'].includes(previous.state)) {
      previous.state='disconnected';
      await request(`${BASE}/sessions/${previous.id}/disconnect`,'POST',{});
    }
    if(active)show('已断开此容器终端。');
  }
  async function connect() {
    if(!active||connecting||!ended())return;
    connecting=true;show('正在创建容器终端…');
    try {
      await disconnect();
      await assets();if(!active)return;
      term?.dispose();pane.replaceChildren();
      term=new window.Terminal({fontFamily:'ui-monospace, monospace',fontSize:14,scrollback:5000,cursorBlink:true,minimumContrastRatio:4.5,theme:palette()});
      fit=new window.FitAddon.FitAddon();term.loadAddon(fit);term.open(pane);
      term.onData(data=>{if(active&&session?.state==='ready')send({type:'input',data});});
      term.attachCustomKeyEventHandler(e=>{
        if(e.type==='keydown'&&(e.metaKey||e.ctrlKey)&&e.key.toLowerCase()==='c'&&term.hasSelection()) {navigator.clipboard?.writeText(term.getSelection()).catch(()=>{});return false;}
        return true;
      });
      const created=await request(`${BASE}/sessions`,'POST',{container_id:containerId,identity,shell:select.value,workspace_id:workspace});
      if(!active){await request(`${BASE}/sessions/${created.id}/disconnect`,'POST',{});return;}
      session=created;
      const url=new URL(`${BASE}/sessions/${session.id}/ws`,location.href);url.protocol=location.protocol==='https:'?'wss:':'ws:';
      const channel=ws=new WebSocket(url);channel.binaryType='arraybuffer';
      channel.onmessage=event=>{
        if(!active||channel!==ws)return;
        if(event.data instanceof ArrayBuffer){term.write(new Uint8Array(event.data));return;}
        let data;try{data=JSON.parse(event.data);}catch{return;}
        if(data.type!=='state')return;
        Object.assign(session,data);
        show(reasons[data.reason]||({'ready':'已连接 · '+select.value,connecting:'正在连接…',failed:'连接失败',disconnected:'会话已结束',closed:'会话已关闭'}[data.state]||data.state));
        if(data.state==='ready'){layout();term.focus();}
      };
      channel.onclose=()=>{if(!active||channel!==ws)return;if(!ended()){session.state='disconnected';show('交互连接已关闭。');}};
      channel.onerror=()=>{if(active&&channel===ws)show('交互连接失败，请检查登录状态或终端运行服务。');};
      layout();
    } catch(error) {await disconnect().catch(()=>{});if(active){session=null;show(error.message);}}
    finally {connecting=false;if(active){connectButton.disabled=!ended();select.disabled=!ended();}}
  }
  const resize=new ResizeObserver(layout);resize.observe(pane);
  // xterm owns Tab and other shell keys; the surrounding Sheet must not trap them.
  const shellKeys=event=>event.stopPropagation();pane.addEventListener('keydown',shellKeys);
  const theme=new MutationObserver(layout);theme.observe(document.documentElement,{attributes:true,attributeFilter:['data-theme-resolved','data-theme-family','style','class']});
  const close=()=>{if(!active)return;active=false;clearInterval(lease);cancelAnimationFrame(frame);resize.disconnect();theme.disconnect();pane.removeEventListener('keydown',shellKeys);window.removeEventListener('pagehide',close);window.removeEventListener('dwrt-session-required',authLost);disconnect().catch(()=>{});term?.dispose();};
  const authLost=()=>{close();pane.replaceChildren();note.textContent='登录已失效，请重新登录后打开容器终端。';connectButton.disabled=disconnectButton.disabled=select.disabled=true;};
  window.addEventListener('pagehide',close);window.addEventListener('dwrt-session-required',authLost);
  const lease=setInterval(async()=>{if(!active||ended())return;const current=session;try{await request(`${BASE}/sessions/${current.id}/lease`,'POST',{});}catch(error){if(!active||session!==current)return;ws?.close();current.state='disconnected';show(error.message);}},30000);
  connectButton.addEventListener('click',connect);
  disconnectButton.addEventListener('click',()=>disconnect().catch(error=>show(error.message)));
  show('选择容器内的 shell 后连接。');
  return {close,escape:()=>{if(active&&session?.state==='ready')send({type:'input',data:'\u001b'});},isActive:()=>!ended()||connecting};
}
