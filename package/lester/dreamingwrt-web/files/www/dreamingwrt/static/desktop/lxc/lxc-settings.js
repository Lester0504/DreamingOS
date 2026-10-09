const esc=v=>String(v??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));

export function settingsMarkup(document,templates,kit){
  const current=document.config.default_template||'';
  const ids=[...new Set([current,...(templates.catalog||[]).filter(v=>v.compatible).map(v=>v.id)])].filter(Boolean);
  return {
    body:`<div class="lxc-config-form"><p class="lxc-muted">这些默认值只用于新建容器。已有容器保留原位置，继续列出和管理，不会迁移数据。</p><label class="dwrt-kit-field" data-dwrt-component="field">默认新建目录<input class="dwrt-kit-input" name="path" value="${esc(document.config.lxcpath)}" placeholder="选择已挂载的持久存储目录"></label><p class="lxc-muted">目录须已存在，并允许通过文件服务写入。保存时检查目录身份和配置版本。</p><label class="dwrt-kit-field" data-dwrt-component="field">默认模板<select class="dwrt-kit-select" name="template"><option value="">每次创建时选择</option>${ids.map(id=>`<option value="${esc(id)}" ${id===current?'selected':''}>${esc(id)}</option>`).join('')}</select></label><p class="lxc-config-message" role="alert"></p></div>`,
    footer:kit.floatingSavebarMarkup({visible:false,message:'修改只影响新建容器',saveLabel:'保存默认值',discardLabel:'撤销修改'})
  };
}

export function mountSettings({element,document,request,isAlive,saved}){
  const path=element.querySelector('[name=path]'),template=element.querySelector('[name=template]');
  let dirty=false,busy=false;
  const sync=()=>{dirty=path.value!==document.config.lxcpath||template.value!==(document.config.default_template||'');element.querySelector('[data-dwrt-savebar]').classList.toggle('is-hidden',!dirty);};
  async function click(event){
    const target=event.target.closest('[data-dwrt-savebar-save],[data-dwrt-savebar-discard]');
    if(!target||!element.contains(target)||busy)return;event.preventDefault();
    if(target.hasAttribute('data-dwrt-savebar-discard')){path.value=document.config.lxcpath;template.value=document.config.default_template||'';sync();return;}
    busy=true;const message=element.querySelector('.lxc-config-message');message.textContent='';
    try{
      if(!path.value.startsWith('/'))throw new Error('请输入持久存储的绝对目录。');
      const ref=path.value===document.config.lxcpath?document.config.storage_ref:{root_id:'',path:path.value};
      const result=await request('/config','PUT',{confirm:true,revision:document.revision,storage_ref:ref,default_template:template.value});
      if(!isAlive())return;
      if(!result.persisted||!result.applied||result.migrated!==false)throw new Error('未确认默认设置已生效，请保留草稿并重新读取。');
      dirty=false;await saved();
    }catch(error){if(isAlive())message.textContent=error.message;}
    finally{busy=false;}
  }
  element.addEventListener('click',click);element.addEventListener('input',sync);element.addEventListener('change',sync);
  return {isDirty:()=>dirty,close(){element.removeEventListener('click',click);element.removeEventListener('input',sync);element.removeEventListener('change',sync);}};
}
