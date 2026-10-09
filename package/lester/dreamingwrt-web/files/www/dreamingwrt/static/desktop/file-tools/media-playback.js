(() => {
  'use strict';
  const files=window.DWRT_FILES,kit=window.DWRT_UI_KIT;
  const esc=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
  const reasons={dependency_missing:'媒体探测或转换组件尚未安装。',encoder_missing:'当前媒体组件缺少 H.264 / AAC 软件编码器。',probe_failed:'无法读取此文件的媒体信息，格式可能不受支持。',probe_timeout:'媒体信息读取超时。',source_unavailable:'原文件已移走或数据盘离线。',storage_unavailable:'请先为 NAS 选择可写数据目录。',session_limit:'已有两个媒体会话，请关闭一个后再试。',track_unsupported:'所选音轨或字幕不支持转换。',subtitle_failed:'所选字幕转换失败。',transcode_failed:'转换失败，当前组件可能不支持文件中的编码。',cache_limit:'转换缓存已达到限制或数据盘空间不足。',session_not_found:'播放会话已过期，请重新连接。',seek_out_of_range:'定位时间超出文件长度。'};
  async function request(route,body){
    if(window.DWRT_NAS){const [path,query='']=route.split('?');return body===undefined?window.DWRT_NAS.request(path,Object.fromEntries(new URLSearchParams(query))):window.DWRT_NAS.post(path,body);}
    const r=await window.DWRT_REQUEST.fetch('/api/v1/nas'+route,{method:body===undefined?'GET':'POST',credentials:'same-origin',cache:'no-store',...(body===undefined?{}:{headers:{'Content-Type':'application/json'},body:JSON.stringify(body)})});
    let p;try{p=await r.json();}catch(_){throw new Error('NAS 媒体组件暂时无法连接。');}const d=p.data||p;
    if(!r.ok||d.error||p.code>=4000)throw Object.assign(new Error(r.status===401?'会话已过期，请重新登录。':r.status===403?'当前账号没有媒体读取权限。':reasons[d.error]||d.message||'媒体请求失败。'),{code:d.error,status:r.status});return d;
  }
  let hlsLoading;
  async function loadHls(){
    if(window.Hls)return window.Hls;
    if(!hlsLoading)hlsLoading=new Promise((resolve,reject)=>{const script=document.createElement('script');script.src='/static/vendor/iptv-hls/hls.min.js';script.onload=()=>resolve(window.Hls);script.onerror=()=>{hlsLoading=null;reject(new Error('HLS 播放组件加载失败。'));};document.head.append(script);});
    return hlsLoading;
  }
  window.DWRT_MEDIA_PLAYBACK={async stream(media,file,options={}){
    const source=await files.stream(file);
    let hls=null;
    if(options.hls){
      const Hls=await loadHls();
      if(Hls?.isSupported()){
        hls=new Hls({xhrSetup:xhr=>{xhr.withCredentials=true;}});
        hls.on(Hls.Events.ERROR,(_,event)=>{if(event.fatal)options.onError?.('播放失败，请检查摄像机编码、存储和登录状态。');});
        hls.loadSource(source);hls.attachMedia(media);
      }else if(media.canPlayType('application/vnd.apple.mpegurl'))media.src=source;
      else throw new Error('当前浏览器不支持 HLS 播放。');
    }else media.src=source;
    if(options.autoplay)media.play().catch(()=>{});
    return {dispose(){hls?.destroy();media.pause();media.removeAttribute('src');media.load();}};
  },attach(media,file,host,options={}){
    const button=(name,label,disabled=false)=>`<button type="button" class="dwrt-kit-button" data-dwrt-component="button" data-playback="${name}" ${disabled?'disabled':''}>${label}</button>`;
    host.classList.add('ft-playback');host.innerHTML=`<div class="ft-toolbar">${button('info','媒体信息')}${button('native','原生播放')}${button('convert','转换播放',true)}</div><div class="ft-playback-options" hidden><label class="dwrt-kit-field">音轨<select class="dwrt-kit-select" data-audio><option value="-1">默认音轨</option></select></label><label class="dwrt-kit-field">字幕<select class="dwrt-kit-select" data-subtitle><option value="-1">关闭字幕</option></select></label><label class="dwrt-kit-field ft-playback-seek">定位时间<input type="range" data-seek min="0" max="0" step="1" value="0"><output data-time>0:00</output></label>${button('seek','定位')}</div><p role="status" data-message>直接播放原文件；需要转换时先读取媒体信息。</p>`;kit.mountAll(host);
    const $=s=>host.querySelector(s),message=text=>{$('[data-message]').textContent=text;};
    let session=null,hls=null,timer=null,version=0,disposed=false,pending=false,metadata=null,offset=0,mode='native',duration=0,attached=null;
    const time=n=>{n=Math.max(0,Math.floor(n||0));return `${Math.floor(n/60)}:${String(n%60).padStart(2,'0')}`;};
    const position=()=>offset+(Number.isFinite(media.currentTime)?media.currentTime:0);
    async function stopSession(){const id=session;session=null;clearInterval(timer);timer=null;if(id)try{await request('/media/sessions/stop',{id});}catch(e){if(e.status!==404&&!disposed)message(reasons[e.code]||e.message);}}
    function detach(){hls?.destroy();hls=null;attached=null;media.querySelectorAll('track[data-nas-subtitle]').forEach(t=>t.remove());}
    function renderInfo(info){metadata=info;duration=Number(info.format?.duration)||0;const streams=info.streams||[];
      $('[data-audio]').innerHTML='<option value="-1">默认音轨</option>'+streams.filter(s=>s.codec_type==='audio').map(s=>`<option value="${s.index}">音轨 ${s.index} · ${esc(s.tags?.language||'未知语言')} · ${esc(s.codec_name)}</option>`).join('');
      $('[data-subtitle]').innerHTML='<option value="-1">关闭字幕</option>'+streams.filter(s=>s.codec_type==='subtitle').map(s=>`<option value="${s.index}" ${s.selectable?'':'disabled'}>字幕 ${s.index} · ${esc(s.tags?.language||'未知语言')} · ${esc(s.codec_name)}${s.selectable?'':'（暂不支持图像字幕）'}</option>`).join('');
      $('.ft-playback-options').hidden=false;$('[data-seek]').max=duration;$('[data-seek]').value=position();$('[data-time]').textContent=time(position())+' / '+time(duration);
      $('[data-playback="convert"]').disabled=!info.hls_available;
    }
    async function poll(id,ticket){
      if(disposed||session!==id||ticket!==version)return;
      try{const s=await request('/media/sessions?id='+encodeURIComponent(id));if(disposed||session!==id||ticket!==version)return;
        if(s.state==='failed'){message(reasons[s.reason]||'媒体处理失败。');await stopSession();return;}
        if(s.metadata&&!metadata)renderInfo(s.metadata);
        if(s.mode==='probe'&&s.state==='ready'){renderInfo(s.metadata);message(s.metadata.hls_available?'已读取真实音轨和字幕。转换播放使用软件编码，最高 720p。':'媒体信息已读取；'+(reasons[s.metadata.hls_reason]||'当前组件不支持转换。'));await stopSession();return;}
        if(s.playlist&&!attached){attached=id;const source=await files.stream(s.playlist);if(disposed||session!==id)return;
          const Hls=await loadHls();if(disposed||session!==id)return;
          if(Hls?.isSupported()){hls=new Hls({startPosition:0,maxBufferLength:20,backBufferLength:10});hls.on(Hls.Events.ERROR,(_e,d)=>{if(d.fatal)message('转换流读取失败，请重新连接。');});hls.loadSource(source);hls.attachMedia(media);}
          else if(media.canPlayType('application/vnd.apple.mpegurl'))media.src=source;
          else throw new Error('当前浏览器不支持 HLS 播放。');
          if(s.subtitle){const track=document.createElement('track');track.dataset.nasSubtitle='';track.kind='subtitles';track.label='所选字幕';track.srclang='und';track.default=true;track.src=await files.stream(s.subtitle);media.append(track);track.addEventListener('load',()=>{track.track.mode='showing';});}
          message('转换播放中。远距离定位会重新生成当前位置的片段。');media.play().catch(()=>message('转换已就绪，点击播放按钮开始。'));
        }
      }catch(e){if(!disposed&&ticket===version){message(reasons[e.code]||e.message);await stopSession();}}
    }
    async function create(type,at=position()){
      if(pending||disposed)return;
      if(type==='hls'&&(!Number.isFinite(at)||at<0||(duration>0&&at>=duration))){message(reasons.seek_out_of_range);return;}
      pending=true;const ticket=++version;
      $('[data-playback="info"]').disabled=true;
      try{
        await stopSession();if(type==='hls'){detach();media.pause();media.removeAttribute('src');media.load();mode='hls';offset=at;}
        message(type==='probe'?'正在读取媒体信息…':'正在转换当前位置，请稍候…');
        const s=await request('/media/sessions',{mode:type,source:{root_id:file.root_id,path:file.path},position_seconds:type==='hls'?at:0,audio_index:type==='hls'?Number($('[data-audio]').value):-1,subtitle_index:type==='hls'?Number($('[data-subtitle]').value):-1});
        if(disposed||ticket!==version){request('/media/sessions/stop',{id:s.id}).catch(()=>{});return;}
        session=s.id;await poll(session,ticket);if(session===s.id)timer=setInterval(()=>poll(s.id,ticket),2000);
      }catch(e){message(reasons[e.code]||e.message);}finally{pending=false;$('[data-playback="info"]').disabled=false;}
    }
    async function native(at=position()){
      ++version;await stopSession();detach();offset=0;mode='native';
      const source=options.source||await files.stream(file);if(disposed)return;
      media.src=source;media.addEventListener('loadedmetadata',()=>{if(disposed||mode!=='native')return;if(Number.isFinite(at)&&at<media.duration)media.currentTime=at;if(options.autoplay)media.play().catch(()=>{});},{once:true});message('直接播放原文件。');
    }
    async function seek(at){if(!Number.isFinite(at)||at<0)return;if(mode==='hls')await create('hls',at);else media.currentTime=at;}
    const onTime=()=>{if(document.activeElement!==$('[data-seek]'))$('[data-seek]').value=position();$('[data-time]').textContent=time(position())+(duration?' / '+time(duration):'');};media.addEventListener('timeupdate',onTime);
    const onError=()=>{if(!disposed&&!pending)message('播放失败：文件编码、存储或会话可能不可用。可读取媒体信息后尝试转换。');};media.addEventListener('error',onError);
    host.addEventListener('input',e=>{if(e.target.matches('[data-seek]'))$('[data-time]').textContent=time(Number(e.target.value))+' / '+time(duration);});
    host.addEventListener('click',e=>{const b=e.target.closest('[data-playback]');if(!b||b.disabled)return;const action=b.dataset.playback;(async()=>{if(action==='info')return create('probe');if(action==='convert'){const at=position();return create('hls',media.ended||(duration>0&&at>=duration)?0:at);}if(action==='native')return native();if(action==='seek')return seek(Number($('[data-seek]').value));})().catch(e=>message(e.message));});
    function dispose(){if(disposed)return;disposed=true;++version;clearInterval(timer);const id=session;session=null;if(id)fetch('/api/v1/nas/media/sessions/stop',{method:'POST',credentials:'same-origin',keepalive:true,headers:{'Content-Type':'application/json'},body:JSON.stringify({id})}).catch(()=>{});detach();media.removeEventListener('timeupdate',onTime);media.removeEventListener('error',onError);removeEventListener('pagehide',dispose);kit.unmount(host);}
    addEventListener('pagehide',dispose);native(options.position||0).catch(e=>message(e.message));
    return {get position(){return position();},get converting(){return mode==='hls';},seek,dispose};
  }};
})();
