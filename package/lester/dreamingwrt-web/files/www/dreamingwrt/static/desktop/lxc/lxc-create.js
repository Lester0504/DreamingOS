const esc=v=>String(v??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const field=(name,label,value='',type='text',extra='')=>`<label class="dwrt-kit-field" data-dwrt-component="field"><span>${label}</span><input class="dwrt-kit-input" name="${name}" type="${type}" value="${esc(value)}" ${extra}></label>`;

export function createMarkup(settings,templates,kit){
  const images=(templates.catalog||[]).filter(v=>v.creatable);
  return {
    body:`<div class="lxc-config-form">${field('name','容器名称','','text','maxlength="63" placeholder="例如 alpine-dev"')}<label class="dwrt-kit-field" data-dwrt-component="field">系统镜像<select class="dwrt-kit-select" name="image">${images.map((v,i)=>`<option value="${i}" ${v.id===settings.config.default_template?'selected':''}>${esc(v.id+' · '+v.build)}</option>`).join('')}</select></label><p class="lxc-muted">来源：Linux Containers 官方镜像目录。构建版本在预检和执行时再次核对。</p>${field('path','已有持久存储目录',settings.config.lxcpath)}<label class="dwrt-kit-field" data-dwrt-component="field">接入现有网桥<select class="dwrt-kit-select" name="bridge"><option value="">选择网桥</option>${(settings.bridges||[]).map(v=>`<option>${esc(v)}</option>`).join('')}</select></label><p class="lxc-muted">容器内通过 DHCP 获取地址，需要所选网桥已有 DHCP 服务。不会配置宿主网络；暂不支持客体静态地址。</p>${field('memory_bytes','内存上限（bytes，0 表示不限制）',134217728,'number','min="0" step="1"')}${field('cpu_weight','CPU 权重（1–10000）',100,'number','min="1" max="10000" step="1"')}<label class="dwrt-kit-field" data-dwrt-component="field">隔离模式<select class="dwrt-kit-select" name="privilege"><option value="unprivileged">非特权（使用已配置的用户映射）</option><option value="privileged">特权容器</option></select></label><label class="lxc-check" data-privileged-confirm hidden><input type="checkbox" name="privileged_confirm">确认以特权模式创建，容器 root 不做用户映射</label><fieldset class="lxc-mounts"><legend>外部目录挂载</legend><div data-create-mounts></div><button class="dwrt-kit-button" data-dwrt-component="button" type="button" data-mount-add>添加挂载</button><p class="lxc-muted">只绑定文件服务允许的目录，默认只读。删除容器不会删除这些外部数据。</p></fieldset><label class="lxc-check"><input type="checkbox" name="autostart">开机自动启动</label>${field('start_order','启动顺序（较小值优先）',0,'number','min="0" max="10000" step="1"')}${field('start_delay','启动后延迟（秒）',0,'number','min="0" max="300" step="1"')}<label class="lxc-check"><input type="checkbox" name="start_after_create">创建后立即启动</label><p class="lxc-muted">未勾选时仅创建并保持停止；开机自启不会触发本次启动。</p><button class="dwrt-kit-button" data-dwrt-component="button" type="button" data-create-preflight>检查创建条件</button><div data-create-preview role="status"></div><p class="lxc-config-message" role="alert"></p></div>`,
    footer:kit.floatingSavebarMarkup({visible:true,message:'先检查创建条件',saveLabel:'提交创建任务',discardLabel:'重置表单'})
  };
}

export function mountCreate({element,settings,templates,request,confirm,submit,isAlive}){
  const images=(templates.catalog||[]).filter(v=>v.creatable),form=element.querySelector('.lxc-config-form');
  const input=name=>form.querySelector(`[name="${name}"]`),message=text=>{form.querySelector('.lxc-config-message').textContent=text;};
  const save=element.querySelector('[data-dwrt-savebar-save]');let dirty=false,busy=false,preview=null,editVersion=0;
  const invalidate=()=>{editVersion++;dirty=true;preview=null;save.disabled=true;form.querySelector('[data-create-preview]').textContent='';form.querySelector('[data-privileged-confirm]').hidden=input('privilege').value!=='privileged';};
  save.disabled=true;
  function body(){
    const image=images[Number(input('image').value)],name=input('name').value;
    if(!/^[A-Za-z0-9][A-Za-z0-9_.-]{0,62}$/.test(name)||name.includes('..'))throw new Error('名称须为 1–63 位字母、数字、点、横线或下划线，并以字母或数字开头。');
    if(!image)throw new Error('没有可创建的镜像，请刷新模板和运行依赖。');
    if(!input('bridge').value)throw new Error('请选择已有网桥。');
    const mounts=[...form.querySelectorAll('[data-mount-row]')].map(row=>({source:{root_id:'',path:row.querySelector('[name=mount_source]').value},target:row.querySelector('[name=mount_target]').value,read_only:row.querySelector('[name=mount_readonly]').checked}));
    const values={};for(const key of ['memory_bytes','cpu_weight','start_order','start_delay']){values[key]=Number(input(key).value);if(!input(key).value||!input(key).checkValidity()||!Number.isSafeInteger(values[key]))throw new Error('请输入有效的整数资源值。');}
    const storage_ref=input('path').value===settings.config.lxcpath?settings.config.storage_ref:{root_id:'',path:input('path').value};
    return {name,payload:{template_id:image.id,build:image.build,storage_ref,bridge:input('bridge').value,network_mode:'dhcp',...values,privilege:input('privilege').value,privileged_confirm:input('privileged_confirm').checked,start_after_create:input('start_after_create').checked,autostart:input('autostart').checked,mounts}};
  }
  async function click(event){
    const button=event.target.closest('button');if(!button||!element.contains(button)||busy)return;
    if(button.matches('[data-mount-add]')){
      if(form.querySelectorAll('[data-mount-row]').length>=8){message('最多添加 8 个目录挂载。');return;}
      const row=document.createElement('div');row.dataset.mountRow='';row.className='lxc-config-form';row.innerHTML=field('mount_source','宿主已有目录')+field('mount_target','容器内挂载目录','','text','placeholder="/mnt/data"')+'<label class="lxc-check"><input type="checkbox" name="mount_readonly" checked>只读</label><button type="button" class="dwrt-kit-button" data-dwrt-component="button" data-mount-remove>移除此挂载</button>';form.querySelector('[data-create-mounts]').append(row);invalidate();return;
    }
    if(button.matches('[data-mount-remove]')){button.closest('[data-mount-row]').remove();invalidate();return;}
    if(button.matches('[data-dwrt-savebar-discard]')){
      form.querySelectorAll('input').forEach(el=>{if(el.type==='checkbox')el.checked=el.defaultChecked;else el.value=el.defaultValue;});form.querySelectorAll('select').forEach(el=>el.selectedIndex=Math.max(0,[...el.options].findIndex(o=>o.defaultSelected)));form.querySelector('[data-create-mounts]').replaceChildren();invalidate();dirty=false;message('');return;
    }
    if(!button.matches('[data-create-preflight],[data-dwrt-savebar-save]'))return;
    busy=true;message('');save.disabled=true;
    try{
      const draft=body(),version=editVersion;
      if(button.matches('[data-create-preflight]')){
        const result=await request('/container/'+encodeURIComponent(draft.name)+'/preflight','POST',{...draft.payload,confirm:true});
        if(!isAlive())return;
        if(version!==editVersion)throw new Error('检查期间表单已修改，请重新检查。');
        if(!result.ok||!result.plan)throw new Error('没有取得有效预检结果。');
        preview=draft;preview.payload.storage_ref=result.plan.storage_ref;preview.payload.mounts=result.plan.mounts;
        form.querySelector('[data-create-preview]').textContent=`检查通过：${draft.name} · ${result.plan.template_id} · ${result.plan.lxcpath} · ${result.plan.bridge} · ${result.plan.privilege==='unprivileged'?'非特权':'特权'} · ${result.will_start?'创建并启动':'仅创建，保持停止'}。`;
      }else{
        if(!preview)throw new Error('请先检查创建条件。');
        if(await confirm('提交创建任务？',preview.name+' · '+(preview.payload.start_after_create?'创建后立即启动。':'仅创建，保持停止。')+' 下载和创建在后台继续，关闭窗口不会取消。')&&isAlive()){
          dirty=false;const accepted=await submit('/container/'+encodeURIComponent(preview.name),'POST',preview.payload);if(accepted===false)dirty=true;
        }
      }
    }catch(error){if(isAlive())message(error.message);}
    finally{busy=false;if(isAlive())save.disabled=!preview;}
  }
  element.addEventListener('click',click);form.addEventListener('input',invalidate);form.addEventListener('change',invalidate);
  return {isDirty:()=>dirty,close(){element.removeEventListener('click',click);form.removeEventListener('input',invalidate);form.removeEventListener('change',invalidate);}};
}
