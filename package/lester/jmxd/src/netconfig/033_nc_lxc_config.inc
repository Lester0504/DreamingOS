/* config.db is the desired configuration authority; LXC files are applied images.
 * Reads never import an external container. Takeover is an explicit CAS write. */
#ifndef NC_LXC_CONFIG_DB
#define NC_LXC_CONFIG_DB g_netconfig_db_path
#endif
#ifndef NC_LXC_CGROUP_CONTROLLERS
#define NC_LXC_CGROUP_CONTROLLERS "/sys/fs/cgroup/cgroup.controllers"
#endif

static int nc_lxc_document_db(sqlite3 **out)
{
    sqlite3 *db=NULL;
    if(sqlite3_open_v2(NC_LXC_CONFIG_DB,&db,SQLITE_OPEN_READWRITE|SQLITE_OPEN_FULLMUTEX,NULL)!=SQLITE_OK){if(db)sqlite3_close(db);return -1;}
    sqlite3_busy_timeout(db,3000);
    if(sqlite3_exec(db,"CREATE TABLE IF NOT EXISTS lxc_config_document("
        "path TEXT PRIMARY KEY,name TEXT NOT NULL,identity TEXT NOT NULL,revision INTEGER NOT NULL,"
        "desired TEXT NOT NULL,applied TEXT NOT NULL,state TEXT NOT NULL DEFAULT 'pending',"
        "previous TEXT NOT NULL DEFAULT '',was_running INTEGER NOT NULL DEFAULT 0,"
        "last_error TEXT NOT NULL DEFAULT '',updated_at INTEGER NOT NULL);"
        "CREATE TABLE IF NOT EXISTS lxc_settings(id INTEGER PRIMARY KEY CHECK(id=1),default_root TEXT NOT NULL,default_template TEXT NOT NULL,revision INTEGER NOT NULL);"
        "CREATE TABLE IF NOT EXISTS lxc_roots(path TEXT PRIMARY KEY,device INTEGER NOT NULL,inode INTEGER NOT NULL);",NULL,NULL,NULL)!=SQLITE_OK){sqlite3_close(db);return -1;}
    *out=db;return 0;
}
static int nc_lxc_document_hash(const char *text,char value[65])
{
    unsigned char digest[32];unsigned int n=0;
    if(!EVP_Digest(text,strlen(text),digest,&n,EVP_sha256(),NULL)||n!=32)return -1;
    for(unsigned i=0;i<n;i++)snprintf(value+i*2,3,"%02x",digest[i]);
    return 0;
}

static int nc_lxc_root_admit(struct json_object *ref,char path[PATH_MAX],struct json_object *out,int writing)
{
    const char *const keys[]={"root_id","path","device","inode",NULL};
    if(!nc_docker_keys(ref,keys)||!nc_docker_string(nc_docker_member(ref,"path"),PATH_MAX-1))return nc_lxc_error(out,"invalid_storage_reference");
    const char *reason=NULL;struct stat st;
    int fd=storage_files_open_dir(nc_json_str_def(ref,"root_id",""),nc_json_str_def(ref,"path",""),writing,path,PATH_MAX,&reason);
    if(fd<0){nc_lxc_string(out,"reason",reason);return nc_lxc_error(out,"lxc_storage_unavailable");}
    int rc=fstat(fd,&st);close(fd);if(rc)return nc_lxc_error(out,"lxc_storage_unavailable");
    if(strchr(path,'\n')||strchr(path,'\r'))return nc_lxc_error(out,"invalid_storage_reference");
    const char *names[]={"device","inode"};uint64_t values[]={(uint64_t)st.st_dev,(uint64_t)st.st_ino};
    for(int i=0;i<2;i++){
        struct json_object *v=nc_docker_member(ref,names[i]);
        if(v&&(!json_object_is_type(v,json_type_int)||(uint64_t)json_object_get_int64(v)!=values[i]))return nc_lxc_error(out,"lxc_storage_changed");
        json_object_object_add(ref,names[i],json_object_new_int64((int64_t)values[i]));
    }
    nc_lxc_string(ref,"path",path);return 0;
}

static int nc_lxc_root_remember(sqlite3 *db,const char *path)
{
    struct stat st;sqlite3_stmt *query=NULL;if(stat(path,&st)||!S_ISDIR(st.st_mode))return -1;
    if(sqlite3_prepare_v2(db,"INSERT OR IGNORE INTO lxc_roots(path,device,inode) VALUES(?1,?2,?3)",-1,&query,NULL)!=SQLITE_OK)return -1;
    sqlite3_bind_text(query,1,path,-1,SQLITE_TRANSIENT);sqlite3_bind_int64(query,2,st.st_dev);sqlite3_bind_int64(query,3,st.st_ino);
    int rc=sqlite3_step(query)==SQLITE_DONE?0:-1;sqlite3_finalize(query);return rc;
}

static struct json_object *nc_lxc_options(const char *text)
{
    const char *prefix="# dwrt.lxc.options = ";size_t length=strlen(prefix);
    for(const char *p=text;*p;){
        const char *end=strchr(p,'\n');size_t n=end?(size_t)(end-p):strlen(p);
        if(n>=length&&!strncmp(p,prefix,length)){
            char *value=strndup(p+length,n-length);struct json_object *result=value?json_tokener_parse(value):NULL;free(value);
            if(result&&json_object_is_type(result,json_type_object))return result;
            json_object_put(result);return NULL;
        }
        if(!end)break;
        p=end+1;
    }
    return NULL;
}

static int nc_lxc_mounts_validate(struct json_object *mounts,struct json_object *out)
{
    if(!mounts||!json_object_is_type(mounts,json_type_array)||json_object_array_length(mounts)>8)return nc_lxc_error(out,"invalid_mounts");
    for(size_t i=0;i<json_object_array_length(mounts);i++){
        struct json_object *item=json_object_array_get_idx(mounts,i);const char *const keys[]={"source","target","read_only",NULL};
        const char *target=nc_json_str_def(item,"target","");struct json_object *readonly=nc_docker_member(item,"read_only");char canonical[PATH_MAX];
        if(!nc_docker_keys(item,keys)||target[0]!='/'||!target[1]||strlen(target)>255||strstr(target,"..")||strchr(target,'\n')||strchr(target,'\r')||!readonly||!json_object_is_type(readonly,json_type_boolean))return nc_lxc_error(out,"invalid_mount");
        for(size_t j=0;j<i;j++)if(!strcmp(target,nc_json_str_def(json_object_array_get_idx(mounts,j),"target","")))return nc_lxc_error(out,"duplicate_mount_target");
        if(nc_lxc_root_admit(nc_docker_member(item,"source"),canonical,out,!json_object_get_boolean(readonly)))return -1;
    }
    return 0;
}

int jmx_lxc_settings_save(struct json_object *cfg,struct json_object *out)
{
    const char *const keys[]={"confirm","revision","storage_ref","default_template",NULL};
    if(nc_docker_confirmation_required(cfg,out))return -1;
    if(!nc_docker_keys(cfg,keys))return nc_lxc_error(out,"invalid_settings_request");
    struct json_object *ref=json_object_new_object(),*input_ref=nc_docker_member(cfg,"storage_ref"),*revision=nc_docker_member(cfg,"revision");
    if(input_ref&&json_object_is_type(input_ref,json_type_object)){
        json_object_object_foreach(input_ref,key,value){json_object_object_add(ref,key,json_object_get(value));}
    }
    sqlite3 *db=NULL;sqlite3_stmt *st=NULL;char path[PATH_MAX],old[PATH_MAX];int rc=-1,transaction=0;
    const char *template=nc_json_str_def(cfg,"default_template","");
    if(!revision||!json_object_is_type(revision,json_type_int)||json_object_get_int64(revision)<0){nc_lxc_error(out,"invalid_config_revision");goto done;}
    if(strlen(template)>80||strchr(template,'\n')||strstr(template,"..")||strchr(template,':')){nc_lxc_error(out,"invalid_template_id");goto done;}
    if(nc_lxc_root_admit(ref,path,out,1)||nc_lxc_path(old,sizeof(old),out))goto done;
    if(nc_lxc_document_db(&db)||sqlite3_exec(db,"BEGIN IMMEDIATE",NULL,NULL,NULL)!=SQLITE_OK)goto storage_error;
    transaction=1;
    if(sqlite3_prepare_v2(db,"SELECT revision FROM lxc_settings WHERE id=1",-1,&st,NULL)!=SQLITE_OK)goto storage_error;
    int64_t current=sqlite3_step(st)==SQLITE_ROW?sqlite3_column_int64(st,0):0;sqlite3_finalize(st);st=NULL;
    if(current!=json_object_get_int64(revision)){nc_lxc_error(out,"lxc_config_revision_conflict");goto done;}
    /* The previous root may be unavailable. Keep its path for diagnosis and
     * rediscovery instead of making its containers disappear. */
    if(nc_lxc_root_remember(db,old)){
        if(sqlite3_prepare_v2(db,"INSERT OR IGNORE INTO lxc_roots(path,device,inode) VALUES(?1,0,0)",-1,&st,NULL)!=SQLITE_OK)goto storage_error;
        sqlite3_bind_text(st,1,old,-1,SQLITE_TRANSIENT);
        if(sqlite3_step(st)!=SQLITE_DONE)goto storage_error;
        sqlite3_finalize(st);st=NULL;
    }
    if(nc_lxc_root_remember(db,path))goto storage_error;
    if(sqlite3_prepare_v2(db,"INSERT INTO lxc_settings(id,default_root,default_template,revision) VALUES(1,?1,?2,?3) ON CONFLICT(id) DO UPDATE SET default_root=excluded.default_root,default_template=excluded.default_template,revision=excluded.revision",-1,&st,NULL)!=SQLITE_OK)goto storage_error;
    sqlite3_bind_text(st,1,path,-1,SQLITE_TRANSIENT);sqlite3_bind_text(st,2,template,-1,SQLITE_TRANSIENT);sqlite3_bind_int64(st,3,current+1);
    if(sqlite3_step(st)!=SQLITE_DONE||sqlite3_exec(db,"COMMIT",NULL,NULL,NULL)!=SQLITE_OK)goto storage_error;
    transaction=0;rc=0;nc_lxc_bool(out,"ok",1);nc_lxc_bool(out,"persisted",1);nc_lxc_bool(out,"applied",1);
    nc_lxc_bool(out,"new_containers_only",1);nc_lxc_bool(out,"migrated",0);json_object_object_add(out,"revision",json_object_new_int64(current+1));goto done;
storage_error:
    nc_lxc_error(out,"lxc_config_storage_failed");
done:
    if(st)sqlite3_finalize(st);
    if(transaction)sqlite3_exec(db,"ROLLBACK",NULL,NULL,NULL);
    if(db)sqlite3_close(db);
    json_object_put(ref);return rc;
}
static struct json_object *nc_lxc_document_row(sqlite3 *db,const char *path)
{
    sqlite3_stmt *st=NULL;struct json_object *row=NULL;
    if(sqlite3_prepare_v2(db,"SELECT identity,revision,desired,applied,state,previous,was_running,last_error FROM lxc_config_document WHERE path=?1",-1,&st,NULL)!=SQLITE_OK)return NULL;
    sqlite3_bind_text(st,1,path,-1,SQLITE_TRANSIENT);
    if(sqlite3_step(st)==SQLITE_ROW){
        row=json_object_new_object();const char *keys[]={"identity","revision","desired","applied","state","previous","was_running","last_error"};
        for(int i=0;i<8;i++){
            if(i==1)json_object_object_add(row,keys[i],json_object_new_int64(sqlite3_column_int64(st,i)));
            else if(i==6)nc_lxc_bool(row,keys[i],sqlite3_column_int(st,i));
            else nc_lxc_string(row,keys[i],(const char *)sqlite3_column_text(st,i));
        }
    }
    sqlite3_finalize(st);return row;
}
static struct json_object *nc_lxc_document_fields(const char *text)
{
    struct json_object *fields=json_object_new_object();char value[80],*end;
    const char *keys[]={"lxc.start.auto","lxc.cgroup2.memory.max","lxc.cgroup2.cpu.weight","lxc.start.order","lxc.start.delay"};
    const char *names[]={"autostart","memory_bytes","cpu_weight","start_order","start_delay"};
    for(int i=0;i<5;i++){
        int count=nc_lxc_config_value(text,keys[i],value,sizeof(value));
        if(count<=0){json_object_object_add(fields,names[i],NULL);continue;}
        if(i==1&&!strcmp(value,"max")){json_object_object_add(fields,names[i],json_object_new_int64(0));continue;}
        errno=0;long long number=strtoll(value,&end,10);
        if(errno||*end||number<0)json_object_object_add(fields,names[i],NULL);
        else if(!i)nc_lxc_bool(fields,names[i],number!=0);
        else json_object_object_add(fields,names[i],json_object_new_int64(number));
    }
    struct json_object *options=nc_lxc_options(text);
    if(options){
        const char *extra[]={"bridge","mounts",NULL};for(int i=0;extra[i];i++){struct json_object *v=nc_docker_member(options,extra[i]);if(v)json_object_object_add(fields,extra[i],json_object_get(v));}
        json_object_put(options);
    }
    return fields;
}

static int nc_lxc_document_runtime_changed(const char *before,const char *after);

struct json_object *jmx_lxc_config_document_get(const char *name)
{
    struct json_object *response=jmx_lxc_container_config_get(name),*d=nc_docker_member(response,"data");
    if(!nc_json_bool_def(d,"ok",0))return response;
    const char *actual=nc_json_str_def(d,"config",""),*path=nc_json_str_def(d,"config_path","");
    char fingerprint[65];if(nc_lxc_document_hash(actual,fingerprint)){nc_lxc_error(d,"lxc_config_fingerprint_failed");return response;}
    nc_lxc_string(d,"fingerprint",fingerprint);json_object_object_add(d,"revision",json_object_new_int64(0));
    nc_lxc_string(d,"state","external");nc_lxc_bool(d,"persisted",0);nc_lxc_bool(d,"applied",1);
    nc_lxc_string(d,"write_reason","lxc_config_takeover_required");
    json_object_object_add(d,"fields",nc_lxc_document_fields(actual));
    json_object_object_add(d,"applied_fields",nc_lxc_document_fields(actual));
    sqlite3 *db=NULL;struct json_object *row=NULL;
    /* Query-only: opening this page must not take ownership or create a schema. */
    if(sqlite3_open_v2(NC_LXC_CONFIG_DB,&db,SQLITE_OPEN_READONLY,NULL)==SQLITE_OK)row=nc_lxc_document_row(db,path);
    if(db)sqlite3_close(db);
    if(row){
        if(strcmp(nc_json_str_def(d,"identity",""),nc_json_str_def(row,"identity","")))nc_lxc_string(d,"write_reason","container_identity_changed");
        else{
            const char *desired=nc_json_str_def(row,"desired",""),*applied=nc_json_str_def(row,"applied","");
            int conflict=strcmp(actual,applied)&&strcmp(actual,desired);
            nc_lxc_string(d,"ownership","managed");nc_lxc_bool(d,"persisted",1);
            nc_lxc_string(d,"state",conflict?"external_conflict":nc_json_str_def(row,"state","pending"));
            nc_lxc_string(d,"write_reason",conflict?"lxc_config_external_conflict":"");
            json_object_object_add(d,"revision",json_object_get(nc_docker_member(row,"revision")));
            json_object_object_add(d,"fields",nc_lxc_document_fields(desired));
            nc_lxc_bool(d,"restart_required",nc_lxc_document_runtime_changed(actual,desired));
            nc_lxc_bool(d,"applied",!strcmp(actual,desired)&&!strcmp(nc_json_str_def(row,"state",""),"idle"));
            nc_lxc_string(d,"last_error",nc_json_str_def(row,"last_error",""));
        }json_object_put(row);
    }
    nc_lxc_bool(d,"config_write",!strcmp(nc_json_str_def(d,"state",""),"external") ||
        !strcmp(nc_json_str_def(d,"state",""),"idle") || !strcmp(nc_json_str_def(d,"state",""),"pending"));
    nc_lxc_bool(d,"takeover_required",!nc_json_bool_def(d,"persisted",0));
    struct json_object *options=nc_lxc_options(actual);
    nc_lxc_bool(d,"network_mounts_write",options!=NULL&&nc_json_bool_def(d,"config_write",0));
    json_object_put(options);
    return response;
}

/* Field-specific patches leave every other line, duplicate and include intact.
 * LXC scalar setters consume the final assignment, including after includes. */
static char *nc_lxc_document_render(const char *text,struct json_object *fields)
{
    const char *keys[]={"lxc.cgroup2.memory.max","lxc.cgroup2.cpu.weight","lxc.net.0.link","lxc.start.auto","lxc.start.order","lxc.start.delay"};
    const char *names[]={"memory_bytes","cpu_weight","bridge","autostart","start_order","start_delay"};
    struct json_object *options=nc_lxc_options(text),*mounts=nc_docker_member(fields,"mounts");
    size_t used=0;char *out=NULL;int trailing_newline=1;FILE *file=open_memstream(&out,&used);if(!file){json_object_put(options);return NULL;}
    for(const char *p=text;*p;){
        const char *end=strchr(p,'\n');size_t n=end?(size_t)(end-p)+1:strlen(p);
        char *line=strndup(p,n);if(!line){fclose(file);free(out);json_object_put(options);return NULL;}char *trim=nc_lxc_trim(line),*eq=strchr(trim,'=');int remove=options&&!strncmp(trim,"# dwrt.lxc.options = ",21);
        if(eq&&*trim!='#'){*eq=0;trim=nc_lxc_trim(trim);for(int i=0;i<6;i++)if(nc_docker_member(fields,names[i])&&!strcmp(trim,keys[i]))remove=1;if(mounts&&!strcmp(trim,"lxc.mount.entry"))remove=1;}
        free(line);if(!remove){fwrite(p,1,n,file);trailing_newline=p[n-1]=='\n';}p+=n;
    }
    if(!trailing_newline)fputc('\n',file);
    for(int i=0;i<6;i++){
        struct json_object *v=nc_docker_member(fields,names[i]);if(!v)continue;
        if(i==2)fprintf(file,"%s = %s\n",keys[i],json_object_get_string(v));
        else if(!i&&!json_object_get_int64(v))fprintf(file,"%s = max\n",keys[i]);
        else fprintf(file,"%s = %lld\n",keys[i],(long long)json_object_get_int64(v));
    }
    if(mounts){
        fputs("lxc.mount.entry =\n",file);
        for(size_t i=0;i<json_object_array_length(mounts);i++){
            struct json_object *m=json_object_array_get_idx(mounts,i);
            fputs("lxc.mount.entry = ",file);nc_lxc_mount_token(file,nc_json_str_def(nc_docker_member(m,"source"),"path",""));fputc(' ',file);nc_lxc_mount_token(file,nc_json_str_def(m,"target","")+1);fprintf(file," none bind,%s,create=dir 0 0\n",nc_json_bool_def(m,"read_only",0)?"ro":"rw");
        }
    }
    if(options){
        const char *extra[]={"bridge","mounts",NULL};for(int i=0;extra[i];i++){struct json_object *v=nc_docker_member(fields,extra[i]);if(v)json_object_object_add(options,extra[i],json_object_get(v));}
        fprintf(file,"# dwrt.lxc.options = %s\n",json_object_to_json_string_ext(options,JSON_C_TO_STRING_PLAIN));
    }
    int failed=fclose(file);json_object_put(options);
    if(failed||used>32768){free(out);return NULL;}
    return out;
}

static int nc_lxc_document_runtime_changed(const char *before,const char *after)
{
    struct json_object *neutral=json_object_new_object();
    nc_lxc_bool(neutral,"autostart",0);
    json_object_object_add(neutral,"start_order",json_object_new_int(0));
    json_object_object_add(neutral,"start_delay",json_object_new_int(0));
    char *a=nc_lxc_document_render(before,neutral),*b=nc_lxc_document_render(after,neutral);
    int changed=!a||!b||strcmp(a,b);free(a);free(b);json_object_put(neutral);return changed;
}

static int nc_lxc_document_validate_fields(struct json_object *fields,struct json_object *out)
{
    const char *const keys[]={"memory_bytes","cpu_weight","bridge","mounts","autostart","start_order","start_delay",NULL};
    if(!nc_docker_keys(fields,keys)||!json_object_object_length(fields))return nc_lxc_error(out,"invalid_config_fields");
    char *controllers=nc_lxc_read_text(NC_LXC_CGROUP_CONTROLLERS,4096);
    int valid=1;
    json_object_object_foreach(fields,key,value){
        if(!strcmp(key,"autostart")){
            if(!json_object_is_type(value,json_type_boolean)){nc_lxc_error(out,"invalid_autostart");valid=0;break;}
            continue;
        }
        if(!strcmp(key,"start_order")||!strcmp(key,"start_delay")){
            int max=!strcmp(key,"start_delay")?300:10000;
            if(!json_object_is_type(value,json_type_int)||json_object_get_int64(value)<0||json_object_get_int64(value)>max){nc_lxc_string(out,"field",key);nc_lxc_error(out,"invalid_autostart_value");valid=0;break;}
            continue;
        }
        if(!strcmp(key,"bridge")){
            if(!json_object_is_type(value,json_type_string)){nc_lxc_error(out,"invalid_bridge");valid=0;break;}
            if(nc_lxc_bridge(json_object_get_string(value),out)){valid=0;break;}
            continue;
        }
        if(!strcmp(key,"mounts")){if(nc_lxc_mounts_validate(value,out)){valid=0;break;}continue;}
        int memory=!strcmp(key,"memory_bytes");int64_t n=json_object_get_int64(value);
        if(!json_object_is_type(value,json_type_int)||(memory?(n!=0&&(n<16777216||n>INT64_C(1152921504606846976))):(n<1||n>10000))){nc_lxc_string(out,"field",key);nc_lxc_error(out,"invalid_config_value");valid=0;break;}
        if(!controllers||!strstr(controllers,memory?"memory":"cpu")){nc_lxc_string(out,"field",key);nc_lxc_error(out,"lxc_cgroup_controller_unavailable");valid=0;break;}
    }
    free(controllers);return valid?0:-1;
}

int jmx_lxc_config_document_save(const char *name,struct json_object *cfg,struct json_object *out)
{
    const char *const keys[]={"id","name","action","confirm","identity","revision","fingerprint","takeover","fields",NULL};
    if(nc_docker_confirmation_required(cfg,out))return -1;
    if(!nc_docker_keys(cfg,keys))return nc_lxc_error(out,"invalid_config_request");
    if(nc_lxc_document_validate_fields(nc_docker_member(cfg,"fields"),out))return -1;
    struct json_object *revision=nc_docker_member(cfg,"revision");
    if(!revision||!json_object_is_type(revision,json_type_int)||json_object_get_int64(revision)<0)return nc_lxc_error(out,"invalid_config_revision");
    char root[PATH_MAX],identity[80],path[PATH_MAX],hash[65];
    if(nc_lxc_identity(name,root,sizeof(root),identity,sizeof(identity),out))return -1;
    if(strcmp(identity,nc_json_str_def(cfg,"identity","")))return nc_lxc_error(out,"container_identity_changed");
    if(snprintf(path,sizeof(path),"%s/%s/config",root,name)>=(int)sizeof(path))return nc_lxc_error(out,"lxc_path_too_long");
    char *actual=nc_lxc_read_text(path,32768),*desired=NULL;
    sqlite3 *db=NULL;sqlite3_stmt *st=NULL;struct json_object *row=NULL;int rc=-1,transaction=0;
    if(!actual||nc_lxc_document_hash(actual,hash)){nc_lxc_error(out,"lxc_config_read_failed");goto done;}
    struct json_object *options=nc_lxc_options(actual),*fields=nc_docker_member(cfg,"fields");int advanced=nc_docker_member(fields,"bridge")||nc_docker_member(fields,"mounts");
    if(advanced&&!options){json_object_put(options);nc_lxc_error(out,"lxc_network_mounts_require_managed_layout");goto done;}
    json_object_put(options);
    if(strcmp(hash,nc_json_str_def(cfg,"fingerprint",""))){nc_lxc_error(out,"lxc_config_external_conflict");goto done;}
    if(nc_lxc_document_db(&db)||sqlite3_exec(db,"BEGIN IMMEDIATE",NULL,NULL,NULL)!=SQLITE_OK){nc_lxc_error(out,"lxc_config_storage_failed");goto done;}transaction=1;
    row=nc_lxc_document_row(db,path);int64_t current=row?json_object_get_int64(nc_docker_member(row,"revision")):0;
    if(current!=json_object_get_int64(revision)){nc_lxc_error(out,"lxc_config_revision_conflict");goto done;}
    if(!row&&!nc_json_bool_def(cfg,"takeover",0)){nc_lxc_error(out,"lxc_config_takeover_required");goto done;}
    if(row&&(strcmp(identity,nc_json_str_def(row,"identity",""))||strcmp(actual,nc_json_str_def(row,"applied","")))){nc_lxc_error(out,"lxc_config_external_conflict");goto done;}
    if(row&&strcmp(nc_json_str_def(row,"state",""),"idle")&&strcmp(nc_json_str_def(row,"state",""),"pending")){nc_lxc_error(out,"lxc_config_recovery_required");goto done;}
    desired=nc_lxc_document_render(row?nc_json_str_def(row,"desired",actual):actual,nc_docker_member(cfg,"fields"));
    if(!desired){nc_lxc_error(out,"lxc_config_too_large");goto done;}
    const char *sql="INSERT INTO lxc_config_document(path,name,identity,revision,desired,applied,state,updated_at) VALUES(?1,?2,?3,?4,?5,?6,'pending',?7) ON CONFLICT(path) DO UPDATE SET revision=excluded.revision,desired=excluded.desired,state='pending',last_error='',updated_at=excluded.updated_at";
    if(sqlite3_prepare_v2(db,sql,-1,&st,NULL)!=SQLITE_OK){nc_lxc_error(out,"lxc_config_storage_failed");goto done;}
    sqlite3_bind_text(st,1,path,-1,SQLITE_TRANSIENT);sqlite3_bind_text(st,2,name,-1,SQLITE_TRANSIENT);sqlite3_bind_text(st,3,identity,-1,SQLITE_TRANSIENT);
    sqlite3_bind_int64(st,4,current+1);sqlite3_bind_text(st,5,desired,-1,SQLITE_TRANSIENT);sqlite3_bind_text(st,6,actual,-1,SQLITE_TRANSIENT);sqlite3_bind_int64(st,7,nc_now_s());
    if(sqlite3_step(st)!=SQLITE_DONE||sqlite3_exec(db,"COMMIT",NULL,NULL,NULL)!=SQLITE_OK){nc_lxc_error(out,"lxc_config_storage_failed");goto done;}transaction=0;
    nc_lxc_bool(out,"ok",1);nc_lxc_bool(out,"persisted",1);nc_lxc_bool(out,"applied",0);nc_lxc_string(out,"state","pending");
    json_object_object_add(out,"revision",json_object_new_int64(current+1));json_object_object_add(out,"fields",nc_lxc_document_fields(desired));
    nc_lxc_bool(out,"restart_required",nc_lxc_document_runtime_changed(actual,desired));rc=0;
done:
    if(st)sqlite3_finalize(st);
    if(transaction)sqlite3_exec(db,"ROLLBACK",NULL,NULL,NULL);
    if(db)sqlite3_close(db);
    json_object_put(row);free(actual);free(desired);return rc;
}

/* The job serializes container actions; revision + fingerprint bind an apply to
 * the saved draft and to the exact file the user reviewed. */
static int nc_lxc_document_plan(const char *name,const char *action,struct json_object *cfg,
                                struct json_object *plan,struct json_object *out)
{
    const char *const keys[]={"id","name","action","confirm","identity","revision","fingerprint","restart_confirm",NULL};
    if(nc_docker_confirmation_required(cfg,out))return -1;
    if(!nc_docker_keys(cfg,keys))return nc_lxc_error(out,"invalid_config_request");
    struct json_object *response=jmx_lxc_config_document_get(name),*d=nc_docker_member(response,"data");
    struct json_object *revision=nc_docker_member(cfg,"revision");int rc=-1;
    if(!nc_json_bool_def(d,"ok",0)){nc_lxc_error(out,nc_json_str_def(d,"error","lxc_config_read_failed"));goto done;}
    if(!revision||!json_object_is_type(revision,json_type_int) ||
       json_object_get_int64(revision)!=json_object_get_int64(nc_docker_member(d,"revision"))){nc_lxc_error(out,"lxc_config_revision_conflict");goto done;}
    if(strcmp(nc_json_str_def(cfg,"identity",""),nc_json_str_def(d,"identity",""))){nc_lxc_error(out,"container_identity_changed");goto done;}
    if(strcmp(nc_json_str_def(cfg,"fingerprint",""),nc_json_str_def(d,"fingerprint",""))){nc_lxc_error(out,"lxc_config_external_conflict");goto done;}
    int recovering=!strcmp(action,"config_recover");
    const char *saved_state=nc_json_str_def(d,"state","");
    if(!nc_json_bool_def(d,"persisted",0) || (!recovering&&strcmp(saved_state,"pending")) ||
       (recovering&&strcmp(saved_state,"applying")&&strcmp(saved_state,"recovery"))){nc_lxc_error(out,"lxc_config_state_conflict");goto done;}
    char state[24];
    if(nc_lxc_state(nc_json_str_def(d,"lxcpath",""),name,state,sizeof(state),out))goto done;
    if(strcmp(state,"RUNNING")&&strcmp(state,"STOPPED")){nc_lxc_error(out,"lxc_config_state_conflict");goto done;}
    if(((!strcmp(state,"RUNNING")&&nc_json_bool_def(d,"restart_required",1))||recovering)&&!nc_json_bool_def(cfg,"restart_confirm",0)){nc_lxc_error(out,"restart_confirmation_required");goto done;}
    if(!nc_cmd_exists("lxc-start")||!nc_cmd_exists("lxc-stop")){nc_lxc_error(out,"lxc_command_missing");goto done;}
    json_object_object_foreach(cfg,key,value){if(strcmp(key,"id"))json_object_object_add(plan,key,json_object_get(value));}
    nc_lxc_string(plan,"name",name);nc_lxc_string(plan,"action",action);
    nc_lxc_string(plan,"lxcpath",nc_json_str_def(d,"lxcpath",""));rc=0;
done:
    json_object_put(response);return rc;
}

static int nc_lxc_document_submit(const char *name,const char *action,struct json_object *cfg,struct json_object *out)
{
    struct json_object *plan=json_object_new_object();char target[256],kind[32];int rc=-1;
    if(nc_lxc_document_plan(name,action,cfg,plan,out))goto done;
    if(snprintf(target,sizeof(target),"%s/%s",nc_json_str_def(plan,"lxcpath",""),name)>=(int)sizeof(target)){nc_lxc_error(out,"lxc_path_too_long");goto done;}
    snprintf(kind,sizeof(kind),"lxc_%s",action);
    rc=nc_container_job_submit(kind,target,json_object_to_json_string_ext(plan,JSON_C_TO_STRING_PLAIN),out);
done:
    json_object_put(plan);return rc;
}

static int nc_lxc_document_replace(const char *path,const char *expected,const char *text)
{
    char temporary[PATH_MAX];struct stat st;int rc=-1;
    int original=open(path,O_RDONLY|O_NOFOLLOW|O_CLOEXEC);
    if(original<0)return -1;
    if(fstat(original,&st)||!S_ISREG(st.st_mode)){close(original);return -1;}
    close(original);
    if(snprintf(temporary,sizeof(temporary),"%s.dwrt-XXXXXX",path)>=(int)sizeof(temporary))return -1;
    int fd=mkstemp(temporary);if(fd<0)return -1;
    size_t length=strlen(text),offset=0;
    if(fchmod(fd,st.st_mode&0777) || (geteuid()==0&&fchown(fd,st.st_uid,st.st_gid)))goto done;
    while(offset<length){ssize_t n=write(fd,text+offset,length-offset);if(n<0&&errno==EINTR)continue;if(n<=0)goto done;offset+=(size_t)n;}
    if(fsync(fd))goto done;
    char *actual=nc_lxc_read_text(path,32768);
    int unchanged=actual&&!strcmp(actual,expected);free(actual);
    if(!unchanged){errno=ESTALE;goto done;}
    if(rename(temporary,path))goto done;
    char directory[PATH_MAX];snprintf(directory,sizeof(directory),"%s",path);char *slash=strrchr(directory,'/');
    if(slash){*slash=0;int parent=open(directory,O_RDONLY|O_DIRECTORY|O_CLOEXEC);if(parent<0)goto done;rc=fsync(parent);close(parent);}else rc=0;
done:
    close(fd);unlink(temporary);return rc;
}

static int nc_lxc_document_finish(sqlite3 *db,const char *path,const char *applied,const char *state,const char *error)
{
    sqlite3_stmt *st=NULL;
    if(sqlite3_prepare_v2(db,"UPDATE lxc_config_document SET applied=?1,state=?2,last_error=?3,updated_at=?4 WHERE path=?5",-1,&st,NULL)!=SQLITE_OK)return -1;
    sqlite3_bind_text(st,1,applied,-1,SQLITE_TRANSIENT);sqlite3_bind_text(st,2,state,-1,SQLITE_TRANSIENT);
    sqlite3_bind_text(st,3,error,-1,SQLITE_TRANSIENT);sqlite3_bind_int64(st,4,nc_now_s());sqlite3_bind_text(st,5,path,-1,SQLITE_TRANSIENT);
    int rc=sqlite3_step(st)==SQLITE_DONE&&sqlite3_changes(db)==1?0:-1;sqlite3_finalize(st);return rc;
}

static int nc_lxc_document_execute(sqlite3 *jobs,const char *id,const char *kind,const char *target,
                                   struct json_object *request,struct nc_exec_result *capture,struct json_object *out)
{
    struct json_object *input=json_object_new_object(),*plan=json_object_new_object(),*row=NULL;
    sqlite3 *db=NULL;sqlite3_stmt *st=NULL;int rc=125,changed=0,stopped=0,was_running=0,restart_needed=1,recovering=!strcmp(kind,"lxc_config_recover");
    char path[PATH_MAX],state[24],expected[256];const char *root=NULL,*name=nc_json_str_def(request,"name","");
    const char *desired=NULL,*previous=NULL,*failure="lxc_config_apply_failed";
    json_object_object_foreach(request,key,value){if(strcmp(key,"lxcpath"))json_object_object_add(input,key,json_object_get(value));}
    if(nc_lxc_document_plan(name,kind+4,input,plan,out))goto done;
    root=nc_json_str_def(plan,"lxcpath","");snprintf(expected,sizeof(expected),"%s/%s",root,name);
    if(strcmp(target,expected)||strcmp(root,nc_json_str_def(request,"lxcpath",""))){nc_lxc_error(out,"lxc_root_changed");goto done;}
    if(snprintf(path,sizeof(path),"%s/config",expected)>=(int)sizeof(path)||nc_lxc_document_db(&db)){nc_lxc_error(out,"lxc_config_storage_failed");goto done;}
    if(sqlite3_exec(db,"BEGIN IMMEDIATE",NULL,NULL,NULL)!=SQLITE_OK)goto storage_error;
    row=nc_lxc_document_row(db,path);
    if(!row||json_object_get_int64(nc_docker_member(row,"revision"))!=json_object_get_int64(nc_docker_member(request,"revision"))){sqlite3_exec(db,"ROLLBACK",NULL,NULL,NULL);nc_lxc_error(out,"lxc_config_revision_conflict");goto done;}
    desired=nc_json_str_def(row,"desired","");previous=nc_json_str_def(row,recovering?"previous":"applied","");
    restart_needed=recovering||nc_lxc_document_runtime_changed(previous,desired);
    struct json_object *options=nc_lxc_options(desired);
    int invalid_options=!recovering&&options&&((nc_docker_member(options,"bridge")&&nc_lxc_bridge(nc_json_str_def(options,"bridge",""),out))||(nc_docker_member(options,"mounts")&&nc_lxc_mounts_validate(nc_docker_member(options,"mounts"),out)));
    json_object_put(options);
    if(invalid_options){sqlite3_exec(db,"ROLLBACK",NULL,NULL,NULL);goto done;}
    if(!*previous){sqlite3_exec(db,"ROLLBACK",NULL,NULL,NULL);nc_lxc_error(out,"lxc_config_recovery_unavailable");goto done;}
    if(nc_lxc_state(root,name,state,sizeof(state),out)){sqlite3_exec(db,"ROLLBACK",NULL,NULL,NULL);goto done;}
    was_running=recovering?nc_json_bool_def(row,"was_running",0):!strcmp(state,"RUNNING");
    if(sqlite3_prepare_v2(db,"UPDATE lxc_config_document SET previous=?1,was_running=?2,state='applying',updated_at=?3 WHERE path=?4",-1,&st,NULL)!=SQLITE_OK){sqlite3_exec(db,"ROLLBACK",NULL,NULL,NULL);goto storage_error;}
    sqlite3_bind_text(st,1,previous,-1,SQLITE_TRANSIENT);sqlite3_bind_int(st,2,was_running);sqlite3_bind_int64(st,3,nc_now_s());sqlite3_bind_text(st,4,path,-1,SQLITE_TRANSIENT);
    if(sqlite3_step(st)!=SQLITE_DONE){sqlite3_exec(db,"ROLLBACK",NULL,NULL,NULL);goto storage_error;}
    sqlite3_finalize(st);st=NULL;
    if(sqlite3_exec(db,"COMMIT",NULL,NULL,NULL)!=SQLITE_OK)goto storage_error;
    nc_lxc_string(out,"name",name);nc_lxc_string(out,"lxcpath",root);nc_lxc_string(out,"identity",nc_json_str_def(plan,"identity",""));
    nc_lxc_bool(out,"remaining_object",1);nc_lxc_bool(out,"persisted",1);nc_lxc_bool(out,"applied",0);
    const char *stop[]={"lxc-stop","-P",root,"-n",name,"-t","30","--nokill",NULL};
    const char *start[]={"lxc-start","-P",root,"-n",name,"-d",NULL};
    if(!strcmp(state,"RUNNING")&&restart_needed){
        if(nc_lxc_job_stage(jobs,id,"config_stop",out))goto done;
        if(nc_exec_argv_capture_ex(stop,40,NC_CONTAINER_OUTPUT_MAX,capture,0)||nc_lxc_state(root,name,state,sizeof(state),out)||strcmp(state,"STOPPED")){failure="lxc_stop_not_confirmed";goto rollback;}
        stopped=1;nc_exec_result_free(capture);
    }
    if(nc_lxc_job_stage(jobs,id,recovering?"config_recover":"config_apply",out))goto done;
    char *actual=nc_lxc_read_text(path,32768),hash[65];
    if(!actual||nc_lxc_document_hash(actual,hash)||strcmp(hash,nc_json_str_def(request,"fingerprint",""))){free(actual);failure="lxc_config_external_conflict";goto rollback;}
    int written=nc_lxc_document_replace(path,actual,recovering?previous:desired);free(actual);
    if(written){failure="lxc_config_write_failed";goto rollback;}changed=1;
    if(was_running&&restart_needed){
        if(nc_lxc_job_stage(jobs,id,"config_start",out))goto done;
        if(nc_exec_argv_capture_ex(start,40,NC_CONTAINER_OUTPUT_MAX,capture,0)){failure="lxc_config_start_failed";goto rollback;}
    }
    if(nc_lxc_state(root,name,state,sizeof(state),out)||strcmp(state,was_running?"RUNNING":"STOPPED")){failure="lxc_state_not_confirmed";goto rollback;}
    actual=nc_lxc_read_text(path,32768);int matches=actual&&!strcmp(actual,recovering?previous:desired);free(actual);
    if(!matches){failure="lxc_config_external_conflict";goto rollback;}
    if(nc_lxc_document_finish(db,path,recovering?previous:desired,recovering?"pending":"idle",""))goto storage_error;
    nc_lxc_bool(out,"ok",1);nc_lxc_bool(out,"applied",!recovering);nc_lxc_bool(out,"recovered",recovering);
    nc_lxc_string(out,"state",state);nc_lxc_string(out,"stage","verified");nc_lxc_bool(out,"readback_required",0);rc=0;goto done;
rollback:;
    int restored=0;struct json_object *observed=json_object_new_object();
    if(!nc_lxc_state(root,name,state,sizeof(state),observed)){
        actual=nc_lxc_read_text(path,32768);
        if(actual&&!strcmp(actual,previous))restored=1;
        else if(!recovering&&actual&&!strcmp(actual,desired)&&!strcmp(state,"STOPPED")&&!nc_lxc_document_replace(path,actual,previous))restored=1;
        free(actual);
        if(restored&&was_running&&(!strcmp(state,"STOPPED"))&&(stopped||changed||recovering)){
            nc_exec_result_free(capture);
            if(nc_exec_argv_capture_ex(start,40,NC_CONTAINER_OUTPUT_MAX,capture,0)||nc_lxc_state(root,name,state,sizeof(state),observed)||strcmp(state,"RUNNING"))restored=0;
        }
    }
    json_object_put(observed);
    nc_lxc_document_finish(db,path,previous,restored?"pending":"recovery",failure);
    nc_lxc_bool(out,"recovered",restored);nc_lxc_bool(out,"recovery_required",!restored);nc_lxc_string(out,"state",state);
    nc_lxc_string(out,"stage","failed");nc_lxc_error(out,failure);goto done;
storage_error:
    nc_lxc_error(out,"lxc_config_storage_failed");
done:
    if(st)sqlite3_finalize(st);
    if(db)sqlite3_close(db);
    json_object_put(row);json_object_put(input);json_object_put(plan);return rc;
}
