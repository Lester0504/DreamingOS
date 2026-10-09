const esc=v=>String(v??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
export function maintenanceMarkup(document,canWrite,capabilities={}){
  const disabled=canWrite?'':'disabled';
  const ability=key=>canWrite&&capabilities[key]?'':'disabled';
  return `<div class="lxc-config-form"><p>目录存储使用完整 rootfs 复制。所有操作要求源容器已停止，复制体保持停止，自启关闭。</p><label class="dwrt-kit-field" data-dwrt-component="field">克隆名称<input class="dwrt-kit-input" name="clone_name" maxlength="63" ${disabled}></label><label class="dwrt-kit-field" data-dwrt-component="field">克隆的外部挂载<select class="dwrt-kit-select" name="mount_policy" ${disabled}><option value="detach">断开外部挂载</option><option value="share">保留共享挂载</option></select></label><label class="lxc-check" data-share-confirm hidden><input type="checkbox" name="share_confirm" ${disabled}>确认复制体与源容器共享相同外部目录，写入会互相影响</label><button type="button" class="dwrt-kit-button" data-dwrt-component="button" data-maintenance="clone" ${ability('clone')}>预检并克隆</button><hr><div class="lxc-actions"><strong>快照</strong><button type="button" class="dwrt-kit-button" data-dwrt-component="button" data-maintenance="snapshot" ${ability('snapshot_create')}>创建快照</button></div><p class="lxc-muted">快照包含容器 rootfs 和配置，不包含外部绑定目录，也不保存运行内存。恢复会覆盖 rootfs；执行前保留一个停止的完整回退容器。</p>${document.items?.length?`<div class="lxc-snapshots">${document.items.map(row=>`<section class="lxc-snapshot"><strong>${esc(row.id)}</strong><span>${esc(row.created_at||'时间未知')}</span><div class="lxc-actions"><button type="button" class="dwrt-kit-button" data-dwrt-component="button" data-maintenance="snapshot_restore" data-snapshot="${esc(row.id)}" ${ability('snapshot_restore')}>恢复</button><button type="button" class="dwrt-kit-button" data-dwrt-component="button" data-maintenance="snapshot_delete" data-snapshot="${esc(row.id)}" ${ability('snapshot_delete')}>删除快照</button></div></section>`).join('')}</div>`:'<p>还没有快照。</p>'}<p class="lxc-config-message" role="alert"></p></div>`;
}

export function mountMaintenance({element,document,name,request,confirm,submit,isAlive,canWrite}){
  let busy=false;const input=key=>element.querySelector(`[name="${key}"]`);
  const change=()=>{element.querySelector('[data-share-confirm]').hidden=input('mount_policy').value!=='share';};
  async function click(event){
    const button=event.target.closest('[data-maintenance]');if(!button||!element.contains(button)||busy||!canWrite||button.disabled)return;
    busy=true;const message=element.querySelector('.lxc-config-message');message.textContent='';
    try{
      const operation=button.dataset.maintenance,body={identity:document.identity,fingerprint:document.fingerprint};
      if(operation==='clone'){
        body.new_name=input('clone_name').value;body.mount_policy=input('mount_policy').value;body.share_confirm=input('share_confirm').checked;
        if(!/^[A-Za-z0-9][A-Za-z0-9_.-]{0,62}$/.test(body.new_name)||body.new_name.includes('..'))throw new Error('请输入有效的新容器名称。');
        if(body.mount_policy==='share'&&!body.share_confirm)throw new Error('请明确确认共享外部挂载。');
      }else if(button.dataset.snapshot){
        const selected=document.items.find(row=>row.id===button.dataset.snapshot);body.snapshot=selected.id;body.snapshot_identity=selected.identity;
      }
      const preview=await request('/container/'+encodeURIComponent(name)+'/maintenance/preflight','POST',{...body,operation,confirm:true});
      if(!isAlive())return;
      if(!preview.ok)throw new Error('未通过维护预检。');
      const wording={clone:['克隆容器？',`创建 ${body.new_name}，完整复制 rootfs，${body.mount_policy==='share'?'保留已确认的共享挂载':'断开外部挂载'}。复制体不启动。`],snapshot:['创建停止状态快照？','完整复制 rootfs 和配置；外部绑定数据不在快照中。'],snapshot_restore:['恢复快照并覆盖 rootfs？',`恢复 ${body.snapshot}。将先保留当前数据的完整回退容器，恢复后目标保持停止。`],snapshot_delete:['永久删除此快照？',`只删除 ${body.snapshot}；不会删除当前容器或外部绑定数据。`]}[operation];
      if(!await confirm(wording[0],name+' · '+wording[1])||!isAlive())return;
      let path='/container/'+encodeURIComponent(name)+'/'+operation,method='POST';
      if(operation==='snapshot_restore'){path='/container/'+encodeURIComponent(name)+'/snapshot/'+encodeURIComponent(body.snapshot)+'/restore';body.restore_confirm=true;}
      if(operation==='snapshot_delete'){path='/container/'+encodeURIComponent(name)+'/snapshot/'+encodeURIComponent(body.snapshot);method='DELETE';}
      await submit(path,method,body);
    }catch(error){if(isAlive())message.textContent=error.message;}
    finally{busy=false;}
  }
  element.addEventListener('click',click);element.addEventListener('change',change);
  return {isDirty:()=>!!input('clone_name').value,close(){element.removeEventListener('click',click);element.removeEventListener('change',change);}};
}
