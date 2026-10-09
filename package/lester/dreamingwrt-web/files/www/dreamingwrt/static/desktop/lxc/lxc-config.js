const esc=value=>String(value??'').replace(/[&<>"']/g,char=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[char]));
const mountRows=(items,enabled)=>items.map(m=>`<div class="lxc-config-form" data-config-mount-row><label class="dwrt-kit-field">宿主已有目录<input class="dwrt-kit-input" name="mount_source" value="${esc(m.source?.path)}" ${enabled?'':'disabled'}></label><label class="dwrt-kit-field">容器内目录<input class="dwrt-kit-input" name="mount_target" value="${esc(m.target)}" ${enabled?'':'disabled'}></label><label class="lxc-check"><input type="checkbox" name="mount_readonly" ${m.read_only?'checked':''} ${enabled?'':'disabled'}>只读挂载</label><button type="button" class="dwrt-kit-button" data-dwrt-component="button" data-config-mount-remove ${enabled?'':'disabled'}>移除此挂载</button></div>`).join('');
const mountValue=items=>JSON.stringify(items.map(m=>({path:m.source?.path||'',target:m.target||'',read_only:!!m.read_only})));
const states={external:'尚未接管',pending:'已保存，待应用',idle:'已应用',applying:'应用中或中断待恢复',recovery:'需要恢复',external_conflict:'检测到外部修改'};

export function configMarkup(document,kit,canWrite){
  const field=(name,label,value,min,max)=>`<label class="dwrt-kit-field" data-dwrt-component="field"><span>${label}</span><input class="dwrt-kit-input" type="number" name="${name}" value="${esc(value)}" min="${min}" max="${max}" step="1" ${canWrite&&document.config_write?'':'disabled'}></label>`;
  return {
    body:`<div class="lxc-config-form"><p data-config-state role="status">${esc(states[document.state]||document.state)}</p><p class="lxc-muted">保存记录待应用配置。运行参数的变更在应用时重启运行中的容器；仅修改自启设置不会重启。</p>${field('memory_bytes','内存上限（bytes，0 表示不限制）',document.fields?.memory_bytes,0,1152921504606846976)}${field('cpu_weight','CPU 权重（1–10000）',document.fields?.cpu_weight,1,10000)}<label class="lxc-check"><input type="checkbox" name="autostart" ${document.fields?.autostart?'checked':''} ${canWrite&&document.config_write?'':'disabled'}>开机自动启动</label>${field('start_order','启动顺序（较小值优先）',document.fields?.start_order??0,0,10000)}${field('start_delay','启动后延迟（秒）',document.fields?.start_delay??0,0,300)}<p class="lxc-muted">自启设置只影响下次开机，不改变当前运行状态。</p><p class="lxc-muted">留空保持原值。CPU 权重用于共享 CPU 的相对分配，不是核数或硬上限。</p><label class="dwrt-kit-field">现有网桥<input class="dwrt-kit-input" name="bridge" value="${esc(document.fields?.bridge)}" ${canWrite&&document.network_mounts_write?'':'disabled'}></label><fieldset class="lxc-mounts"><legend>外部目录挂载</legend><div data-config-mounts>${mountRows(document.fields?.mounts||[],canWrite&&document.network_mounts_write)}</div><button class="dwrt-kit-button" data-dwrt-component="button" type="button" data-config-mount-add ${canWrite&&document.network_mounts_write?'':'disabled'}>添加挂载</button></fieldset><p class="lxc-muted">${document.network_mounts_write?'变更只修改容器的网桥连接和绑定目录，应用时重新启动运行中的容器；不配置宿主网络，也不删除外部目录。':'此配置尚无可验证的网络/挂载布局，保留原配置，仅开放资源字段。'}</p><label class="lxc-check" data-config-takeover ${document.takeover_required?'':'hidden'}><input type="checkbox" name="takeover" ${canWrite?'':'disabled'}>允许平台管理这些字段，保留其他配置与 include</label><div class="lxc-actions"><button class="dwrt-kit-button" data-dwrt-component="button" type="button" data-config-apply ${canWrite&&document.state==='pending'?'':'disabled'}>应用已保存配置</button><button class="dwrt-kit-button" data-dwrt-component="button" type="button" data-config-recover ${canWrite&&['applying','recovery'].includes(document.state)?'':'disabled'}>恢复上次配置</button></div><p class="lxc-config-message" role="alert"></p><details><summary>当前应用的原始配置</summary><pre data-config-raw>${esc(document.config)}</pre></details></div>`,
    footer:canWrite&&document.config_write?kit.floatingSavebarMarkup({visible:false,message:'修改待保存；保存不会重启容器',saveLabel:'保存配置',discardLabel:'撤销修改'}):''
  };
}

export function mountConfig({element,document:initial,name,request,confirm,submit,isAlive,canWrite}){
  let current=initial,busy=false,dirty=false;
  let locked=[];
  const setBusy=value=>{
    busy=value;
    if(value){
      locked=[...element.querySelectorAll('.lxc-config-form input,.lxc-config-form select,.lxc-config-form button,[data-dwrt-savebar] button')].map(node=>[node,node.disabled]);
      locked.forEach(([node])=>{node.disabled=true;});
    }else{locked.forEach(([node,disabled])=>{if(node.isConnected)node.disabled=disabled;});locked=[];}
  };
  const fields=['memory_bytes','cpu_weight','start_order','start_delay'];
  const input=key=>element.querySelector(`[name="${key}"]`);
  const message=value=>{element.querySelector('.lxc-config-message').textContent=value;};
  const value=key=>String(current.fields?.[key]??(key.startsWith('start_')?0:''));
  const mounts=()=>[...element.querySelectorAll('[data-config-mount-row]')].map(row=>{
    const path=row.querySelector('[name=mount_source]').value,previous=current.fields?.mounts?.find(m=>m.source?.path===path);
    return {source:previous?.source||{root_id:'',path},target:row.querySelector('[name=mount_target]').value,read_only:row.querySelector('[name=mount_readonly]').checked};
  });
  const reset=()=>{input('autostart').checked=!!current.fields?.autostart;fields.forEach(key=>{input(key).value=value(key);});input('bridge').value=value('bridge');element.querySelector('[data-config-mounts]').innerHTML=mountRows(current.fields?.mounts||[],canWrite&&current.network_mounts_write);};
  const sync=()=>{
    dirty=input('autostart').checked!==!!current.fields?.autostart||fields.some(key=>input(key).value!==value(key))||(current.network_mounts_write&&(input('bridge').value!==value('bridge')||mountValue(mounts())!==mountValue(current.fields?.mounts||[])));
    element.querySelector('[data-dwrt-savebar]')?.classList.toggle('is-hidden',!dirty);
    element.querySelector('[data-config-apply]').disabled=!canWrite||busy||dirty||current.state!=='pending';
  };
  const reload=async()=>{
    const next=await request('/container/'+encodeURIComponent(name)+'/config');
    if(!isAlive())return;
    current=next;reset();
    element.querySelector('[data-config-state]').textContent=states[next.state]||next.state;
    element.querySelector('[data-config-takeover]').hidden=!next.takeover_required;
    element.querySelector('[data-config-raw]').textContent=next.config;
    sync();
  };
  async function click(event){
    const mountButton=event.target.closest('[data-config-mount-add],[data-config-mount-remove]');
    if(mountButton&&element.contains(mountButton)&&!mountButton.disabled&&!busy&&canWrite){
      if(mountButton.hasAttribute('data-config-mount-remove'))mountButton.closest('[data-config-mount-row]').remove();
      else if(element.querySelectorAll('[data-config-mount-row]').length<8)element.querySelector('[data-config-mounts]').insertAdjacentHTML('beforeend',mountRows([{source:{path:''},target:'/mnt/data',read_only:true}],true));
      sync();return;
    }
    const target=event.target.closest('[data-dwrt-savebar-save],[data-dwrt-savebar-discard],[data-config-apply],[data-config-recover]');
    if(!target||!element.contains(target)||target.disabled)return;
    event.preventDefault();event.stopPropagation();if(busy||!canWrite)return;
    if(target.hasAttribute('data-dwrt-savebar-discard')){reset();message('');sync();return;}
    busy=true;message('');
    try{
      const baseline={identity:current.identity,revision:current.revision,fingerprint:current.fingerprint};
      if(target.hasAttribute('data-dwrt-savebar-save')){
        const patch={};
        for(const key of fields){
          const node=input(key);if(node.value===value(key)||node.value==='')continue;
          if(!node.checkValidity()||!Number.isSafeInteger(Number(node.value)))throw new Error('请输入有效的整数。');
          if(key==='memory_bytes'&&Number(node.value)!==0&&Number(node.value)<16777216)throw new Error('内存上限至少为 16 MiB（16777216 bytes），或填写 0。');
          patch[key]=Number(node.value);
        }
        if(input('autostart').checked!==!!current.fields?.autostart)patch.autostart=input('autostart').checked;
        if(current.network_mounts_write){
          if(input('bridge').value!==value('bridge'))patch.bridge=input('bridge').value;
          const nextMounts=mounts();if(mountValue(nextMounts)!==mountValue(current.fields?.mounts||[]))patch.mounts=nextMounts;
        }
        if(!Object.keys(patch).length)throw new Error('没有可保存的字段。');
        if(current.takeover_required&&!input('takeover').checked)throw new Error('请先确认接管这些配置字段。');
        setBusy(true);
        const result=await request('/container/'+encodeURIComponent(name)+'/config','PUT',{...baseline,confirm:true,takeover:input('takeover').checked,fields:patch});
        if(!isAlive())return;
        if(!result.persisted)throw new Error('配置未持久化，请保留草稿并重试。');
        await reload();message('配置已保存，尚未应用。');
      }else{
        const recovering=target.hasAttribute('data-config-recover');
        if(dirty)throw new Error('请先保存或撤销当前修改。');
        const approved=await confirm(recovering?'恢复上次应用的配置？':'应用已保存配置？',name+' · '+(recovering?'恢复前次配置，并尝试恢复原运行状态。当前草稿保留。':current.restart_required===false?'仅更新开机配置，容器当前运行状态保持不变。':'运行中的容器将正常停止并重新启动，服务会暂时中断。已停止的容器保持停止。'));
        if(approved&&isAlive())await submit('/container/'+encodeURIComponent(name)+'/config/'+(recovering?'recover':'apply'),'POST',{...baseline,restart_confirm:true});
      }
    }catch(error){if(isAlive())message(error.message);}
    finally{setBusy(false);if(isAlive())sync();}
  }
  element.addEventListener('click',click);element.addEventListener('input',sync);
  return {isDirty:()=>dirty,close(){element.removeEventListener('click',click);element.removeEventListener('input',sync);}};
}
