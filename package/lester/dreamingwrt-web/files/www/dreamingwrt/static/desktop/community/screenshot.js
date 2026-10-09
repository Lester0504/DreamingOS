// Capture one frame, stop every media track, then edit locally until confirmation.
export async function captureScreenshot(root,limits) {
 let stream, cancelled=false;
 const abort=()=>{cancelled=true;for(const track of stream?.getTracks()||[])track.stop();};
 root.addEventListener('community-unmount',abort,{once:true});
 const source=document.createElement('canvas');
 try {
  stream=await navigator.mediaDevices.getDisplayMedia({video:true,audio:false});
  if(cancelled)return null;
  const video=document.createElement('video');video.srcObject=stream;video.muted=true;await video.play();
  source.width=video.videoWidth;source.height=video.videoHeight;source.getContext('2d').drawImage(video,0,0);video.pause();video.srcObject=null;
 }catch(e){if(e.name==='NotAllowedError'||e.name==='AbortError')return null;throw e;}
 finally{for(const track of stream?.getTracks()||[])track.stop();root.removeEventListener('community-unmount',abort);}
 return editScreenshot(root,source,limits);
}
export function editScreenshot(root,source,limits) {
 return new Promise(resolve=>{
  const d=document.createElement('dialog');d.className='community-dialog community-screenshot';
  d.innerHTML='<header><strong>截图标注</strong><button class="dwrt-kit-button" data-cancel>取消</button></header><div class="community-capture-tools"><label class="dwrt-kit-field" data-dwrt-component="field"><span>工具</span><select class="dwrt-kit-select" data-tool><option value="crop">选区</option><option value="pen">画笔</option><option value="arrow">箭头</option><option value="rect">矩形</option></select></label><label class="dwrt-kit-field" data-dwrt-component="field"><span>颜色</span><input class="dwrt-kit-input" type="color" value="#ed4848" data-color></label><label class="dwrt-kit-field" data-dwrt-component="field"><span>笔宽</span><select class="dwrt-kit-select" data-width><option value="3">细</option><option value="6">中</option><option value="12">粗</option></select></label><button class="dwrt-kit-button" data-undo>撤销</button><button class="dwrt-kit-button" data-confirm>确认图片</button></div><p>拖动框选范围，再用画笔、箭头或矩形标注。确认后可预览，点击发送才上传。</p><canvas aria-label="截图编辑区域"></canvas><p role="status"></p>';
  root.append(d);const canvas=d.querySelector('canvas');canvas.width=source.width;canvas.height=source.height;
  const ctx=canvas.getContext('2d');let edits=[],active=null,crop=null,result=null;
  function stroke(c,e){if(e.tool==='crop')return;c.strokeStyle=e.color;c.lineWidth=e.width;c.lineCap='round';c.lineJoin='round';const a=e.points[0],b=e.points.at(-1);c.beginPath();if(e.tool==='rect')c.rect(a.x,a.y,b.x-a.x,b.y-a.y);else{c.moveTo(a.x,a.y);if(e.tool==='pen')for(const p of e.points)c.lineTo(p.x,p.y);else{c.lineTo(b.x,b.y);const angle=Math.atan2(b.y-a.y,b.x-a.x),size=e.width*5;for(const offset of [-.5,.5]){c.moveTo(b.x,b.y);c.lineTo(b.x-size*Math.cos(angle+offset),b.y-size*Math.sin(angle+offset));}}}c.stroke();}
  function draw(){ctx.clearRect(0,0,canvas.width,canvas.height);ctx.drawImage(source,0,0);crop=null;for(const e of [...edits,...(active?[active]:[])]){if(e.tool==='crop'){const a=e.points[0],b=e.points.at(-1);crop={x:Math.min(a.x,b.x),y:Math.min(a.y,b.y),w:Math.abs(a.x-b.x),h:Math.abs(a.y-b.y)};}else stroke(ctx,e);}if(crop){ctx.save();ctx.strokeStyle='#fff';ctx.lineWidth=Math.max(2,source.width/500);ctx.setLineDash([10,6]);ctx.strokeRect(crop.x,crop.y,crop.w,crop.h);ctx.restore();}}
  const point=e=>{const r=canvas.getBoundingClientRect();return {x:Math.max(0,Math.min(canvas.width,(e.clientX-r.left)*canvas.width/r.width)),y:Math.max(0,Math.min(canvas.height,(e.clientY-r.top)*canvas.height/r.height))};};
  canvas.onpointerdown=e=>{canvas.setPointerCapture(e.pointerId);active={tool:d.querySelector('[data-tool]').value,color:d.querySelector('[data-color]').value,width:Number(d.querySelector('[data-width]').value),points:[point(e)]};};
  canvas.onpointermove=e=>{if(!active)return;active.points.push(point(e));draw();};
  canvas.onpointerup=e=>{if(!active)return;active.points.push(point(e));edits.push(active);active=null;draw();};
  canvas.onpointercancel=()=>{active=null;draw();};
  d.querySelector('[data-undo]').onclick=()=>{edits.pop();draw();};d.querySelector('[data-cancel]').onclick=()=>d.close();
  d.querySelector('[data-confirm]').onclick=async()=>{const area=crop&&crop.w>=2&&crop.h>=2?crop:{x:0,y:0,w:source.width,h:source.height},full=document.createElement('canvas');full.width=source.width;full.height=source.height;const f=full.getContext('2d');f.drawImage(source,0,0);for(const e of edits)stroke(f,e);let scale=Math.min(1,limits.image_dimension/Math.max(area.w,area.h),Math.sqrt(limits.image_pixels/(area.w*area.h)));
   for(let i=0;i<6;i++){const out=document.createElement('canvas');out.width=Math.max(1,Math.round(area.w*scale));out.height=Math.max(1,Math.round(area.h*scale));out.getContext('2d').drawImage(full,area.x,area.y,area.w,area.h,0,0,out.width,out.height);const blob=await new Promise(r=>out.toBlob(r,'image/png'));if(blob&&blob.size<=limits.image_bytes){result=new File([blob],'screenshot.png',{type:'image/png'});d.close();return;}scale*=.72;}d.querySelector('[role=status]').textContent='图片仍超出限制，请缩小选区后重试。';};
  const cancel=()=>d.close();root.addEventListener('community-unmount',cancel,{once:true});
  d.addEventListener('close',()=>{root.removeEventListener('community-unmount',cancel);window.DWRT_UI_KIT?.unmount?.(d);d.remove();resolve(result);},{once:true});window.DWRT_UI_KIT?.mountAll?.(d);d.showModal();draw();
 });
}
