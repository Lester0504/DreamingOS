/* Directory storage: full copies, stopped sources, explicit external-mount policy. */
static struct json_object *nc_lxc_origin(const char *path)
{
    sqlite3 *db=NULL;sqlite3_stmt *st=NULL;struct json_object *r=NULL;
    if(sqlite3_open_v2(NC_LXC_CONFIG_DB,&db,SQLITE_OPEN_READONLY,NULL)==SQLITE_OK&&
       sqlite3_prepare_v2(db,"SELECT source_json FROM lxc_origin WHERE path=?1",-1,&st,NULL)==SQLITE_OK){
        sqlite3_bind_text(st,1,path,-1,SQLITE_TRANSIENT);
        if(sqlite3_step(st)==SQLITE_ROW)r=json_tokener_parse((const char *)sqlite3_column_text(st,0));
    }
    if(st)sqlite3_finalize(st);
    if(db)sqlite3_close(db);
    return r;
}

static int nc_lxc_snapshot_name(const char *name)
{
    if(!name||strncmp(name,"snap",4)||!name[4]||strlen(name)>24)return 0;
    for(const char *p=name+4;*p;p++)if(!isdigit((unsigned char)*p))return 0;
    return 1;
}

static int nc_lxc_snapshot_entries(const char *root,const char *name,struct json_object *items,struct json_object *out)
{
    char directory[PATH_MAX],path[PATH_MAX];struct stat st;
    if(snprintf(directory,sizeof(directory),"%s/%s/snaps",root,name)>=(int)sizeof(directory))return nc_lxc_error(out,"lxc_path_too_long");
    if(lstat(directory,&st)){if(errno==ENOENT)return 0;return nc_lxc_error(out,"lxc_snapshots_unreadable");}
    if(!S_ISDIR(st.st_mode))return nc_lxc_error(out,"lxc_snapshots_unreadable");
    DIR *dir=opendir(directory);struct dirent *entry;if(!dir)return nc_lxc_error(out,"lxc_snapshots_unreadable");int rc=0;
    while((entry=readdir(dir))){
        if(!nc_lxc_snapshot_name(entry->d_name))continue;
        if(json_object_array_length(items)>=128){rc=nc_lxc_error(out,"lxc_snapshot_limit");break;}
        if(snprintf(path,sizeof(path),"%s/%s",directory,entry->d_name)>=(int)sizeof(path)||lstat(path,&st)||!S_ISDIR(st.st_mode)){rc=nc_lxc_error(out,"lxc_snapshot_invalid");break;}
        char identity[80];snprintf(identity,sizeof(identity),"%llu:%llu",(unsigned long long)st.st_dev,(unsigned long long)st.st_ino);
        struct json_object *row=json_object_new_object();nc_lxc_string(row,"id",entry->d_name);nc_lxc_string(row,"identity",identity);nc_lxc_string(row,"path",path);
        nc_lxc_string(row,"backend","dir");nc_lxc_string(row,"source_container",name);nc_lxc_string(row,"copy_mode","full");nc_lxc_bool(row,"external_mounts_included",0);
        char timestamp[PATH_MAX];
        if(snprintf(timestamp,sizeof(timestamp),"%s/%s/ts",directory,entry->d_name)>=(int)sizeof(timestamp)){json_object_put(row);rc=nc_lxc_error(out,"lxc_path_too_long");break;}
        char *text=nc_lxc_read_text(timestamp,128);
        nc_lxc_string(row,"created_at",text?nc_lxc_trim(text):"");free(text);json_object_array_add(items,row);
    }
    closedir(dir);return rc;
}

static int nc_lxc_maintenance_source(const char *name,struct json_object *out,struct json_object **document,struct json_object **origin)
{
    *document=jmx_lxc_config_document_get(name);struct json_object *d=nc_docker_member(*document,"data");
    if(!nc_json_bool_def(d,"ok",0))return nc_lxc_error(out,nc_json_str_def(d,"error","lxc_config_read_failed"));
    const char *root=nc_json_str_def(d,"lxcpath","");char expected[PATH_MAX],actual[PATH_MAX],resolved[PATH_MAX];struct stat st;
    *origin=nc_lxc_origin(nc_json_str_def(d,"config_path",""));
    if(!*origin||strcmp(nc_json_str_def(d,"ownership",""),"managed"))return nc_lxc_error(out,"lxc_maintenance_requires_managed_container");
    struct json_object *options=nc_lxc_options(nc_json_str_def(d,"config",""));
    if(options){json_object_object_foreach(options,key,value){json_object_object_add(*origin,key,json_object_get(value));}json_object_put(options);}
    if(!nc_json_bool_def(d,"applied",0)||strcmp(nc_json_str_def(d,"state",""),"idle"))return nc_lxc_error(out,"lxc_config_state_conflict");
    if(snprintf(expected,sizeof(expected),"%s/%s/rootfs",root,name)>=(int)sizeof(expected)||
       nc_lxc_config_value(nc_json_str_def(d,"config",""),"lxc.rootfs.path",actual,sizeof(actual))!=1 || strncmp(actual,"dir:",4)||strcmp(actual+4,expected)||
       !realpath(expected,resolved)||strcmp(expected,resolved)||lstat(expected,&st)||!S_ISDIR(st.st_mode))return nc_lxc_error(out,"lxc_storage_backend_unsupported");
    return 0;
}

static int nc_lxc_maintenance_list(const char *name,struct json_object *out)
{
    struct json_object *document=NULL,*origin=NULL,*items=json_object_new_array();int rc=-1;
    if(nc_lxc_maintenance_source(name,out,&document,&origin))goto done;
    struct json_object *d=nc_docker_member(document,"data");
    if(nc_lxc_snapshot_entries(nc_json_str_def(d,"lxcpath",""),name,items,out))goto done;
    nc_lxc_string(out,"name",name);nc_lxc_string(out,"identity",nc_json_str_def(d,"identity",""));nc_lxc_string(out,"fingerprint",nc_json_str_def(d,"fingerprint",""));
    nc_lxc_string(out,"copy_mode","full");nc_lxc_string(out,"backend","dir");nc_lxc_bool(out,"external_mounts_included",0);
    nc_lxc_bool(out,"has_external_mounts",json_object_array_length(nc_docker_member(origin,"mounts"))>0);
    nc_lxc_bool(out,"ok",1);json_object_object_add(out,"items",json_object_get(items));rc=0;
done:
    json_object_put(items);json_object_put(document);json_object_put(origin);return rc;
}

static int nc_lxc_copy_space(const char *root,const char *name,int copies,struct json_object *out)
{
    char path[PATH_MAX];struct statvfs fs;struct nc_exec_result r={0};
    if(snprintf(path,sizeof(path),"%s/%s/rootfs",root,name)>=(int)sizeof(path))return nc_lxc_error(out,"lxc_path_too_long");
    const char *argv[]={"du","-sk",path,NULL};int rc=nc_exec_argv_capture_ex(argv,15,1024,&r,0);char *end=NULL;
    unsigned long long used=r.output?strtoull(r.output,&end,10):0;int valid=!rc&&end&&end!=r.output&&isspace((unsigned char)*end)&&used<=UINT64_MAX/4096;
    nc_exec_result_free(&r);
    if(!valid||statvfs(root,&fs))return nc_lxc_error(out,"lxc_storage_usage_unavailable");
    uint64_t needed=(uint64_t)used*1024*copies+UINT64_C(67108864);
    json_object_object_add(out,"required_available_bytes",json_object_new_int64(needed));
    return (uint64_t)fs.f_bavail*fs.f_frsize>=needed?0:nc_lxc_error(out,"lxc_storage_insufficient");
}

static int nc_lxc_maintenance_plan(const char *name,const char *action,struct json_object *cfg,struct json_object *plan,struct json_object *out,int preview)
{
    const char *const keys[]={"id","name","action","operation","confirm","identity","fingerprint","new_name","mount_policy","share_confirm","snapshot","snapshot_identity","restore_confirm",NULL};
    struct json_object *document=NULL,*origin=NULL,*items=NULL;int rc=-1;
    if(!preview&&nc_docker_confirmation_required(cfg,out))return -1;
    if(!nc_docker_keys(cfg,keys))return nc_lxc_error(out,"invalid_maintenance_request");
    if(strcmp(action,"clone")&&strcmp(action,"snapshot")&&strcmp(action,"snapshot_restore")&&strcmp(action,"snapshot_delete"))return nc_lxc_error(out,"unsupported_action");
    if(nc_lxc_maintenance_source(name,out,&document,&origin))goto done;
    struct json_object *d=nc_docker_member(document,"data");const char *root=nc_json_str_def(d,"lxcpath","");
    if(strcmp(nc_json_str_def(cfg,"identity",""),nc_json_str_def(d,"identity",""))){nc_lxc_error(out,"container_identity_changed");goto done;}
    if(strcmp(nc_json_str_def(cfg,"fingerprint",""),nc_json_str_def(d,"fingerprint",""))){nc_lxc_error(out,"lxc_config_external_conflict");goto done;}
    char state[24];if(nc_lxc_state(root,name,state,sizeof(state),out))goto done;
    if(strcmp(state,"STOPPED")){nc_lxc_error(out,"container_must_be_stopped");goto done;}
    if(!nc_cmd_exists(!strcmp(action,"clone")?"lxc-copy":"lxc-snapshot")||(!strcmp(action,"snapshot_restore")&&!nc_cmd_exists("lxc-copy"))){nc_lxc_error(out,"lxc_command_missing");goto done;}
    if(strcmp(action,"snapshot_delete")&&nc_lxc_copy_space(root,name,!strcmp(action,"snapshot_restore")?2:1,out))goto done;
    json_object_object_foreach(cfg,key,value){if(strcmp(key,"id")&&strcmp(key,"operation")&&strcmp(key,"action"))json_object_object_add(plan,key,json_object_get(value));}
    nc_lxc_string(plan,"name",name);nc_lxc_string(plan,"action",action);nc_lxc_string(plan,"lxcpath",root);nc_lxc_bool(plan,"confirm",1);
    nc_lxc_string(plan,"copy_mode","full");nc_lxc_bool(plan,"external_mounts_included",0);
    if(!strcmp(action,"clone")){
        const char *newname=nc_json_str_def(cfg,"new_name",""),*policy=nc_json_str_def(cfg,"mount_policy","detach");
        if(!nc_lxc_name_valid(newname)||!strcmp(newname,name)){nc_lxc_error(out,"invalid_clone_name");goto done;}
        if(strcmp(policy,"detach")&&strcmp(policy,"share")){nc_lxc_error(out,"invalid_mount_policy");goto done;}
        if(!strcmp(policy,"share")&&!nc_json_bool_def(cfg,"share_confirm",0)){nc_lxc_error(out,"shared_mount_confirmation_required");goto done;}
        struct json_object *roots=nc_lxc_roots();int exists=0;
        for(size_t i=0;i<json_object_array_length(roots);i++){
            char path[PATH_MAX];struct stat st;const char *r=json_object_get_string(json_object_array_get_idx(roots,i));
            if(snprintf(path,sizeof(path),"%s/%s",r,newname)>=(int)sizeof(path)||!lstat(path,&st)){exists=1;break;}
        }
        json_object_put(roots);if(exists){nc_lxc_error(out,"lxc_name_exists");goto done;}
        nc_lxc_string(plan,"mount_policy",policy);nc_lxc_bool(plan,"share_confirm",!strcmp(policy,"share"));
    }else if(!strcmp(action,"snapshot_restore")||!strcmp(action,"snapshot_delete")){
        const char *snap=nc_json_str_def(cfg,"snapshot","");struct json_object *selected=NULL;
        if(!nc_lxc_snapshot_name(snap)){nc_lxc_error(out,"invalid_snapshot_name");goto done;}
        items=json_object_new_array();if(nc_lxc_snapshot_entries(root,name,items,out))goto done;
        for(size_t i=0;i<json_object_array_length(items);i++){struct json_object *item=json_object_array_get_idx(items,i);if(!strcmp(nc_json_str_def(item,"id",""),snap))selected=item;}
        if(!selected){nc_lxc_error(out,"lxc_snapshot_not_found");goto done;}
        if(strcmp(nc_json_str_def(cfg,"snapshot_identity",""),nc_json_str_def(selected,"identity",""))){nc_lxc_error(out,"lxc_snapshot_changed");goto done;}
        if(!strcmp(action,"snapshot_restore")&&!preview&&!nc_json_bool_def(cfg,"restore_confirm",0)){nc_lxc_error(out,"restore_confirmation_required");goto done;}
    }
    rc=0;
done:
    json_object_put(document);json_object_put(origin);json_object_put(items);return rc;
}

static int nc_lxc_maintenance_submit(const char *name,const char *action,struct json_object *cfg,struct json_object *out,int preview)
{
    struct json_object *plan=json_object_new_object();char target[256],kind[32];int rc=-1;
    if(nc_lxc_maintenance_plan(name,action,cfg,plan,out,preview))goto done;
    if(preview){nc_lxc_bool(out,"ok",1);json_object_object_add(out,"plan",json_object_get(plan));rc=0;goto done;}
    if(snprintf(target,sizeof(target),"%s/%s",nc_json_str_def(plan,"lxcpath",""),name)>=(int)sizeof(target)){nc_lxc_error(out,"lxc_path_too_long");goto done;}
    snprintf(kind,sizeof(kind),"lxc_%s",action);rc=nc_container_job_submit(kind,target,json_object_to_json_string_ext(plan,JSON_C_TO_STRING_PLAIN),out);
done:
    json_object_put(plan);return rc;
}

/* lxc-copy rewrites hostname/MAC/rootfs. Platform policy clears autostart and
 * disconnects bind mounts by default; only explicit sharing retains them. */
static int nc_lxc_copy_finish(const char *root,const char *name,const char *policy,struct json_object *origin,struct json_object *out)
{
    char path[PATH_MAX];if(snprintf(path,sizeof(path),"%s/%s/config",root,name)>=(int)sizeof(path))return nc_lxc_error(out,"lxc_path_too_long");
    char *actual=nc_lxc_read_text(path,32768),*updated=NULL,*detached=NULL;size_t length=0;int rc=-1;
    if(!actual)return nc_lxc_error(out,"lxc_config_read_failed");
    if(!strcmp(policy,"detach")){
        struct json_object *patch=json_object_new_object();json_object_object_add(patch,"mounts",json_object_new_array());detached=nc_lxc_document_render(actual,patch);json_object_put(patch);
        if(!detached){free(actual);return nc_lxc_error(out,"lxc_config_too_large");}
    }
    FILE *f=open_memstream(&updated,&length);if(!f){free(actual);free(detached);return -1;}
    for(const char *p=detached?detached:actual;*p;){
        const char *end=strchr(p,'\n');size_t n=end?(size_t)(end-p)+1:strlen(p);char *line=strndup(p,n),*trim=nc_lxc_trim(line),*eq=strchr(trim,'=');int omit=0;
        if(eq&&*trim!='#'){*eq=0;trim=nc_lxc_trim(trim);omit=!strcmp(trim,"lxc.start.auto")||!strcmp(trim,"lxc.log.file");}
        free(line);if(!omit)fwrite(p,1,n,f);p+=n;
    }
    fprintf(f,"\nlxc.start.auto = 0\nlxc.log.file = %s/%s/lxc.log\n",root,name);
    if(!strcmp(policy,"detach"))fputs("lxc.mount.entry =\n",f);
    if(fclose(f)||length>32768){nc_lxc_error(out,"lxc_config_too_large");goto done;}
    if(nc_lxc_document_replace(path,actual,updated)){nc_lxc_error(out,"lxc_config_write_failed");goto done;}
    nc_lxc_string(origin,"name",name);nc_lxc_string(origin,"lxcpath",root);nc_lxc_bool(origin,"autostart",0);
    if(!strcmp(policy,"detach"))json_object_object_add(origin,"mounts",json_object_new_array());
    if(nc_lxc_created_record(name,origin,out))goto done;
    char state[24];if(nc_lxc_state(root,name,state,sizeof(state),out)||strcmp(state,"STOPPED")){nc_lxc_error(out,"lxc_state_not_confirmed");goto done;}
    rc=0;
done:
    free(actual);free(updated);free(detached);return rc;
}

static int nc_lxc_maintenance_execute(sqlite3 *jobs,const char *id,const char *kind,const char *target,struct json_object *request,struct nc_exec_result *capture,struct json_object *out)
{
    struct json_object *input=json_object_new_object(),*plan=json_object_new_object(),*document=NULL,*origin=NULL,*before=json_object_new_array(),*after=json_object_new_array();int rc=125;
    const char *name=nc_json_str_def(request,"name",""),*action=kind+4,*root=nc_json_str_def(request,"lxcpath","");char expected[256],backup[64]="";
    json_object_object_foreach(request,key,value){if(strcmp(key,"lxcpath")&&strcmp(key,"copy_mode")&&strcmp(key,"external_mounts_included"))json_object_object_add(input,key,json_object_get(value));}
    if(nc_lxc_maintenance_plan(name,action,input,plan,out,0))goto done;
    if(snprintf(expected,sizeof(expected),"%s/%s",root,name)>=(int)sizeof(expected)||strcmp(expected,target)||strcmp(root,nc_json_str_def(plan,"lxcpath",""))){nc_lxc_error(out,"lxc_root_changed");goto done;}
    if(nc_lxc_maintenance_source(name,out,&document,&origin))goto done;
    nc_lxc_string(out,"name",name);nc_lxc_string(out,"lxcpath",root);nc_lxc_string(out,"identity",nc_json_str_def(plan,"identity",""));nc_lxc_bool(out,"remaining_object",1);nc_lxc_string(out,"copy_mode","full");nc_lxc_bool(out,"external_mounts_included",0);
    if(!strcmp(action,"clone")){
        const char *newname=nc_json_str_def(plan,"new_name","");nc_lxc_string(out,"new_name",newname);nc_lxc_string(out,"mount_policy",nc_json_str_def(plan,"mount_policy","detach"));
        char path[PATH_MAX];struct stat st;snprintf(path,sizeof(path),"%s/%s",root,newname);
        nc_lxc_string(out,"remaining_copy_path",path);
        if(nc_lxc_job_stage(jobs,id,"clone",out))goto done;
        const char *argv[]={"lxc-copy","-P",root,"-n",name,"-N",newname,"-p",root,"-B","dir",NULL};
        rc=nc_exec_argv_capture_ex(argv,300,NC_CONTAINER_OUTPUT_MAX,capture,0);
        nc_lxc_bool(out,"remaining_copy",!lstat(path,&st));
        if(rc){nc_lxc_error(out,"lxc_clone_failed");goto done;}
        if(nc_lxc_copy_finish(root,newname,nc_json_str_def(plan,"mount_policy","detach"),origin,out)){rc=125;goto done;}
    }else{
        const char *snap=nc_json_str_def(plan,"snapshot","");
        if(nc_lxc_snapshot_entries(root,name,before,out))goto done;
        if(!strcmp(action,"snapshot_restore")){
            snprintf(backup,sizeof(backup),"dwrt-rollback-%.16s",id+4);nc_lxc_string(out,"rollback_container",backup);
            if(nc_lxc_job_stage(jobs,id,"restore_backup",out))goto done;
            const char *copy[]={"lxc-copy","-P",root,"-n",name,"-N",backup,"-p",root,"-B","dir",NULL};
            rc=nc_exec_argv_capture_ex(copy,300,NC_CONTAINER_OUTPUT_MAX,capture,0);
            struct json_object *backup_origin=json_tokener_parse(json_object_to_json_string_ext(origin,JSON_C_TO_STRING_PLAIN));
            struct json_object *backup_result=json_object_new_object();
            int finish=rc?0:nc_lxc_copy_finish(root,backup,"share",backup_origin,backup_result);json_object_put(backup_origin);json_object_put(backup_result);
            if(rc||finish){rc=125;nc_lxc_error(out,"lxc_restore_backup_failed");goto done;}
            nc_lxc_bool(out,"rollback_ready",1);nc_exec_result_free(capture);
        }
        if(nc_lxc_job_stage(jobs,id,action,out)){rc=125;goto done;}
        const char *create[]={"lxc-snapshot","-P",root,"-n",name,NULL};
        const char *restore[]={"lxc-snapshot","-P",root,"-n",name,"-r",snap,NULL};
        const char *remove[]={"lxc-snapshot","-P",root,"-n",name,"-d",snap,NULL};
        rc=nc_exec_argv_capture_ex(!strcmp(action,"snapshot")?create:!strcmp(action,"snapshot_restore")?restore:remove,300,NC_CONTAINER_OUTPUT_MAX,capture,0);
        if(rc){nc_lxc_error(out,"lxc_snapshot_action_failed");goto done;}
        if(!strcmp(action,"snapshot_restore")){
            /* Restore keeps the snapshot's configuration. Re-import exactly that
             * applied image; the separate full backup stays available to undo. */
            if(nc_lxc_created_record(name,origin,out)){rc=125;goto done;}
            char state[24];if(nc_lxc_state(root,name,state,sizeof(state),out)||strcmp(state,"STOPPED")){rc=125;nc_lxc_error(out,"lxc_state_not_confirmed");goto done;}
            char newroot[PATH_MAX],identity[80];if(nc_lxc_identity(name,newroot,sizeof(newroot),identity,sizeof(identity),out)){rc=125;goto done;}
            nc_lxc_string(out,"identity",identity);nc_lxc_string(out,"snapshot",snap);
        }else{
            if(nc_lxc_snapshot_entries(root,name,after,out)){rc=125;goto done;}
            if(!strcmp(action,"snapshot")){
                const char *newid=NULL;int added=0;
                for(size_t i=0;i<json_object_array_length(after);i++){
                    const char *candidate=nc_json_str_def(json_object_array_get_idx(after,i),"id","");int exists=0;
                    for(size_t j=0;j<json_object_array_length(before);j++)if(!strcmp(candidate,nc_json_str_def(json_object_array_get_idx(before,j),"id","")))exists=1;
                    if(!exists){newid=candidate;added++;}
                }
                if(added!=1){rc=125;nc_lxc_error(out,"lxc_snapshot_not_confirmed");goto done;}nc_lxc_string(out,"snapshot",newid);
            }else{
                for(size_t i=0;i<json_object_array_length(after);i++)if(!strcmp(snap,nc_json_str_def(json_object_array_get_idx(after,i),"id",""))){rc=125;nc_lxc_error(out,"lxc_snapshot_delete_not_confirmed");goto done;}
                nc_lxc_string(out,"snapshot",snap);
            }
        }
    }
    nc_lxc_bool(out,"ok",1);nc_lxc_string(out,"state","STOPPED");nc_lxc_string(out,"stage","verified");nc_lxc_bool(out,"readback_required",0);rc=0;
done:
    json_object_put(input);json_object_put(plan);json_object_put(document);json_object_put(origin);json_object_put(before);json_object_put(after);return rc;
}
