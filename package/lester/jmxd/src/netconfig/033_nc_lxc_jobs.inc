/* Reserve both ends of a clone; a create or another clone must not race its destination. */
static int nc_lxc_jobs_conflict(sqlite3 *db,const char *request)
{
    struct json_object *current=json_tokener_parse(request);sqlite3_stmt *st=NULL;int rc=-1;
    const char *names[]={nc_json_str_def(current,"name",""),nc_json_str_def(current,"new_name",""),NULL};
    if(sqlite3_prepare_v2(db,"SELECT request_json FROM container_job WHERE substr(kind,1,4)='lxc_' AND state IN ('queued','running')",-1,&st,NULL)!=SQLITE_OK)goto done;
    int step;rc=0;
    while((step=sqlite3_step(st))==SQLITE_ROW){
        struct json_object *other=json_tokener_parse((const char *)sqlite3_column_text(st,0));
        const char *existing[]={nc_json_str_def(other,"name",""),nc_json_str_def(other,"new_name",""),NULL};
        for(int i=0;names[i];i++)for(int j=0;existing[j];j++)if(*names[i]&&!strcmp(names[i],existing[j]))rc=1;
        json_object_put(other);if(rc)break;
    }
    if(!rc&&step!=SQLITE_DONE)rc=-1;
done:
    if(st)sqlite3_finalize(st);
    json_object_put(current);return rc;
}

/* LXC uses the existing container_job store and worker, with engine-scoped reads. */
static int nc_lxc_job_kind(const char *kind)
{
    return kind && (!strcmp(kind,"lxc_start") || !strcmp(kind,"lxc_stop") ||
        !strcmp(kind,"lxc_restart") || !strcmp(kind,"lxc_destroy") ||
        !strcmp(kind,"lxc_config_apply") || !strcmp(kind,"lxc_config_recover") || !strcmp(kind,"lxc_create") ||
        !strcmp(kind,"lxc_clone") || !strcmp(kind,"lxc_snapshot") || !strcmp(kind,"lxc_snapshot_restore") || !strcmp(kind,"lxc_snapshot_delete"));
}

static int nc_lxc_state(const char *root,const char *name,char *state,size_t size,struct json_object *out)
{
    const char *const argv[]={"lxc-info","-P",root,"-n",name,"-sH",NULL};struct nc_exec_result result={0};
    int rc=nc_lxc_exec_read(argv,5,1024,&result,out);
    if(!rc && result.output && (!strcmp(result.output,"RUNNING") || !strcmp(result.output,"STOPPED") ||
       !strcmp(result.output,"FROZEN") || !strcmp(result.output,"STARTING") || !strcmp(result.output,"STOPPING")))
        snprintf(state,size,"%s",result.output);
    else if(!rc)rc=nc_lxc_error(out,"lxc_state_invalid");
    nc_exec_result_free(&result);return rc;
}

static int nc_lxc_job_stage(sqlite3 *db,const char *id,const char *stage,struct json_object *result)
{
    sqlite3_stmt *st=NULL;nc_lxc_string(result,"stage",stage);
    nc_lxc_bool(result,"readback_required",1);
    if(sqlite3_prepare_v2(db,"UPDATE container_job SET result_json=?1,updated_at=?2 WHERE id=?3 AND state='running'",-1,&st,NULL)!=SQLITE_OK)return -1;
    sqlite3_bind_text(st,1,json_object_to_json_string_ext(result,JSON_C_TO_STRING_PLAIN),-1,SQLITE_TRANSIENT);
    sqlite3_bind_int64(st,2,nc_now_s());sqlite3_bind_text(st,3,id,-1,SQLITE_TRANSIENT);
    int ok=sqlite3_step(st)==SQLITE_DONE && sqlite3_changes(db)==1;sqlite3_finalize(st);return ok?0:-1;
}

static int nc_lxc_bridge(const char *name,struct json_object *out);
static int nc_lxc_mount_token(FILE *file,const char *text);
#include "033_nc_lxc_config.inc"
#include "033_nc_lxc_create.inc"
#include "033_nc_lxc_maintenance.inc"

static int nc_lxc_validate_action(const char *name,const char *action,struct json_object *cfg,
                                  struct json_object *canonical,struct json_object *out)
{
    const char *const keys[]={"id","name","action","confirm","force","force_confirm","timeout","identity",NULL};
    char kind[32],root[PATH_MAX],identity[80],state[24]="";
    snprintf(kind,sizeof(kind),"lxc_%s",action?action:"");
    if(nc_docker_confirmation_required(cfg,out))return -1;
    if(!nc_lxc_job_kind(kind)){
        const char *pending[]={"create","clone","snapshot","snapshot_restore","config_set",NULL};
        for(int i=0;pending[i];i++)if(action&&!strcmp(action,pending[i])){
            nc_lxc_string(out,"reason","lxc_control_pipeline_pending");nc_lxc_bool(out,"persisted",0);nc_lxc_bool(out,"applied",0);
            return nc_lxc_error(out,"capability_disabled");
        }
        return nc_lxc_error(out,"unsupported_action");
    }
    if(!nc_docker_keys(cfg,keys))return nc_lxc_error(out,"invalid_action_fields");
    struct json_object *force=nc_docker_member(cfg,"force"),*timeout=nc_docker_member(cfg,"timeout");
    if((force&&!json_object_is_type(force,json_type_boolean)) ||
       (timeout&&(!json_object_is_type(timeout,json_type_int)||json_object_get_int(timeout)<1||json_object_get_int(timeout)>120)))
        return nc_lxc_error(out,"invalid_stop_parameters");
    int forced=force&&json_object_get_boolean(force);
    if(forced && strcmp(action,"stop"))return nc_lxc_error(out,"force_only_for_stop");
    if(forced && !nc_json_bool_def(cfg,"force_confirm",0))return nc_lxc_error(out,"force_confirmation_required");
    if(nc_lxc_identity(name,root,sizeof(root),identity,sizeof(identity),out))return -1;
    struct json_object *expected=nc_docker_member(cfg,"identity");
    if(expected && (!nc_docker_string(expected,79)||strcmp(identity,json_object_get_string(expected))))
        return nc_lxc_error(out,"container_identity_changed");
    if(nc_lxc_state(root,name,state,sizeof(state),out))return -1;
    if(!strcmp(action,"start")||!strcmp(action,"restart")){
        char path[PATH_MAX];
        if(snprintf(path,sizeof(path),"%s/%s/config",root,name)>=(int)sizeof(path))return nc_lxc_error(out,"lxc_path_too_long");
        char *text=nc_lxc_read_text(path,32768);struct json_object *options=text?nc_lxc_options(text):NULL;
        int invalid=options&&((nc_docker_member(options,"bridge")&&nc_lxc_bridge(nc_json_str_def(options,"bridge",""),out))||
            (nc_docker_member(options,"mounts")&&nc_lxc_mounts_validate(nc_docker_member(options,"mounts"),out)));
        json_object_put(options);free(text);if(invalid)return -1;
    }
    const char *command=!strcmp(action,"start")?"lxc-start":!strcmp(action,"destroy")?"lxc-destroy":"lxc-stop";
    if(!nc_cmd_exists(command)||(!strcmp(action,"restart")&&!nc_cmd_exists("lxc-start")))
        return nc_lxc_error(out,"lxc_command_missing");
    if((!strcmp(action,"start")||!strcmp(action,"destroy")) && strcmp(state,"STOPPED"))
        return nc_lxc_error(out,"container_must_be_stopped");
    if((!strcmp(action,"stop")||!strcmp(action,"restart")) && strcmp(state,"RUNNING"))
        return nc_lxc_error(out,"container_not_running");
    nc_lxc_string(canonical,"name",name);nc_lxc_string(canonical,"action",action);
    nc_lxc_string(canonical,"lxcpath",root);nc_lxc_string(canonical,"identity",identity);
    nc_lxc_bool(canonical,"confirm",1);nc_lxc_bool(canonical,"force",forced);
    nc_lxc_bool(canonical,"force_confirm",forced);
    json_object_object_add(canonical,"timeout",json_object_new_int(timeout?json_object_get_int(timeout):30));
    return 0;
}

int jmx_lxc_container_action(const char *name,const char *action,struct json_object *cfg,struct json_object *out)
{
    if(action&&!strcmp(action,"snapshot_list"))return nc_lxc_maintenance_list(name,out);
    if(action&&!strcmp(action,"maintenance_preflight"))return nc_lxc_maintenance_submit(name,nc_json_str_def(cfg,"operation",""),cfg,out,1);
    if(action&&(!strcmp(action,"clone")||!strcmp(action,"snapshot")||!strcmp(action,"snapshot_restore")||!strcmp(action,"snapshot_delete")))return nc_lxc_maintenance_submit(name,action,cfg,out,0);
    if(action&&(!strcmp(action,"create")||!strcmp(action,"create_preflight")))return nc_lxc_create_submit(name,cfg,out,!strcmp(action,"create_preflight"));
    if(action && !strcmp(action,"config_set"))return jmx_lxc_config_document_save(name,cfg,out);
    if(action && (!strcmp(action,"config_apply")||!strcmp(action,"config_recover")))return nc_lxc_document_submit(name,action,cfg,out);
    struct json_object *canonical=json_object_new_object();char target[256],kind[32];int rc=-1;
    if(nc_lxc_validate_action(name,action,cfg,canonical,out))goto done;
    if(snprintf(target,sizeof(target),"%s/%s",nc_json_str_def(canonical,"lxcpath",""),name)>=(int)sizeof(target)){
        nc_lxc_error(out,"lxc_path_too_long");goto done;
    }
    snprintf(kind,sizeof(kind),"lxc_%s",action);
    rc=nc_container_job_submit(kind,target,json_object_to_json_string_ext(canonical,JSON_C_TO_STRING_PLAIN),out);
done:
    json_object_put(canonical);return rc;
}

static int nc_lxc_job_execute(sqlite3 *db,const char *id,const char *kind,const char *target,
                              struct json_object *request,struct nc_exec_result *capture,struct json_object *result)
{
    if(!strcmp(kind,"lxc_clone")||!strcmp(kind,"lxc_snapshot")||!strcmp(kind,"lxc_snapshot_restore")||!strcmp(kind,"lxc_snapshot_delete"))return nc_lxc_maintenance_execute(db,id,kind,target,request,capture,result);
    if(!strcmp(kind,"lxc_create"))return nc_lxc_create_execute(db,id,target,request,capture,result);
    if(!strcmp(kind,"lxc_config_apply")||!strcmp(kind,"lxc_config_recover"))
        return nc_lxc_document_execute(db,id,kind,target,request,capture,result);
    const char *name=nc_json_str_def(request,"name",""),*action=kind+4;
    const char *const keys[]={"name","action","lxcpath","identity","confirm","force","force_confirm","timeout",NULL};
    struct json_object *validation=json_object_new_object(),*input=json_object_new_object();
    char expected_target[256],state[24]="";int rc=125;
    if(!nc_docker_keys(request,keys) || strcmp(action,nc_json_str_def(request,"action",""))){nc_lxc_error(result,"invalid_persisted_request");goto done;}
    json_object_object_foreach(request,key,value){if(strcmp(key,"lxcpath"))json_object_object_add(input,key,json_object_get(value));}
    if(nc_lxc_validate_action(name,action,input,validation,result))goto done;
    const char *root=nc_json_str_def(validation,"lxcpath","");
    snprintf(expected_target,sizeof(expected_target),"%s/%s",root,name);
    if(strcmp(target,expected_target)||strcmp(root,nc_json_str_def(request,"lxcpath",""))){nc_lxc_error(result,"lxc_root_changed");goto done;}
    nc_lxc_string(result,"name",name);nc_lxc_string(result,"lxcpath",root);
    nc_lxc_string(result,"identity",nc_json_str_def(validation,"identity",""));nc_lxc_bool(result,"remaining_object",1);
    if(nc_lxc_job_stage(db,id,action,result))goto done;
    int timeout=nc_json_int_def(validation,"timeout",30);char seconds[16];snprintf(seconds,sizeof(seconds),"%d",timeout);
    const char *start[]={"lxc-start","-P",root,"-n",name,"-d",NULL};
    /* --nokill prevents graceful timeout from silently escalating to SIGKILL. */
    const char *stop[]={"lxc-stop","-P",root,"-n",name,"-t",seconds,"--nokill",NULL};
    const char *force[]={"lxc-stop","-P",root,"-n",name,"-k",NULL};
    const char *destroy[]={"lxc-destroy","-P",root,"-n",name,NULL};
    const char *const *argv=!strcmp(action,"start")?start:!strcmp(action,"destroy")?destroy:nc_json_bool_def(validation,"force",0)?force:stop;
    rc=nc_exec_argv_capture_ex(argv,timeout+10,NC_CONTAINER_OUTPUT_MAX,capture,0);
    if(rc){nc_lxc_error(result,capture->timed_out?"lxc_action_timeout":"lxc_action_failed");goto readback;}
    if(!strcmp(action,"restart")){
        if(nc_lxc_state(root,name,state,sizeof(state),result)||strcmp(state,"STOPPED")){
            rc=125;nc_lxc_error(result,"lxc_stop_not_confirmed");goto readback;
        }
        nc_lxc_bool(result,"stopped",1);
        if(nc_lxc_job_stage(db,id,"start",result)){rc=125;goto done;}
        nc_exec_result_free(capture);rc=nc_exec_argv_capture_ex(start,40,NC_CONTAINER_OUTPUT_MAX,capture,0);
        if(rc)nc_lxc_error(result,"lxc_restart_start_failed");
    }
readback:
    if(!strcmp(action,"destroy")){
        char directory[PATH_MAX];struct stat st;snprintf(directory,sizeof(directory),"%s/%s",root,name);
        int absent=lstat(directory,&st)<0&&errno==ENOENT;nc_lxc_bool(result,"remaining_object",!absent);
        if(!rc&&!absent){rc=125;nc_lxc_error(result,"lxc_destroy_not_confirmed");}
    }else{
        struct json_object *observed=json_object_new_object();
        int read_rc=nc_lxc_state(root,name,state,sizeof(state),observed);
        if(!read_rc)nc_lxc_string(result,"state",state);
        else json_object_object_add(result,"readback_error",json_object_get(observed));
        if(!rc&&(read_rc||strcmp(state,!strcmp(action,"stop")?"STOPPED":"RUNNING"))){rc=125;nc_lxc_error(result,"lxc_state_not_confirmed");}
        json_object_put(observed);
    }
    nc_lxc_bool(result,"ok",rc==0);nc_lxc_bool(result,"readback_required",rc!=0);
    nc_lxc_string(result,"stage",rc?"failed":"verified");
done:
    json_object_put(validation);json_object_put(input);return rc;
}
