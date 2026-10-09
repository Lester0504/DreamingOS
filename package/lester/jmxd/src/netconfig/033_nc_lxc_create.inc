/* Creation accepts catalogue identifiers and admitted storage references only. */
#include <net/if.h>
#ifndef NC_LXC_DEFAULT_CONFIG
#define NC_LXC_DEFAULT_CONFIG "/etc/lxc/default.conf"
#endif
#ifndef NC_LXC_SUBUID
#define NC_LXC_SUBUID "/etc/subuid"
#endif
#ifndef NC_LXC_SUBGID
#define NC_LXC_SUBGID "/etc/subgid"
#endif
#ifndef NC_LXC_BRIDGE_ROOT
#define NC_LXC_BRIDGE_ROOT "/sys/class/net"
#endif

static int nc_lxc_subid(const char *path,unsigned long *base)
{
    char *text=nc_lxc_read_text(path,32768),*save=NULL;if(!text)return -1;
    int rc=-1;
    for(char *line=strtok_r(text,"\n",&save);line;line=strtok_r(NULL,"\n",&save)){
        char user[64],extra;unsigned long start,count;
        if(sscanf(line,"%63[^:]:%lu:%lu%c",user,&start,&count,&extra)==3 &&
           (!strcmp(user,"root")||!strcmp(user,"0"))&&start>=65536&&count>=65536&&start<=UINT32_MAX-65536){*base=start;rc=0;break;}
    }
    free(text);return rc;
}

static int nc_lxc_bridge(const char *name,struct json_object *out)
{
    if(!name||!*name||strlen(name)>=IFNAMSIZ)return nc_lxc_error(out,"invalid_bridge");
    for(const char *p=name;*p;p++)if(!isalnum((unsigned char)*p)&&*p!='_'&&*p!='-'&&*p!='.')return nc_lxc_error(out,"invalid_bridge");
    char path[PATH_MAX];struct stat st;
    if(snprintf(path,sizeof(path),"%s/%s/bridge",NC_LXC_BRIDGE_ROOT,name)>=(int)sizeof(path)||stat(path,&st)||!S_ISDIR(st.st_mode))return nc_lxc_error(out,"lxc_bridge_unavailable");
    return 0;
}

static int nc_lxc_create_plan(const char *name,struct json_object *cfg,struct json_object *plan,struct json_object *out,int confirmation)
{
    const char *const keys[]={"id","name","action","confirm","template_id","build","storage_ref","bridge","network_mode","memory_bytes","cpu_weight","privilege","privileged_confirm","start_after_create","autostart","start_order","start_delay","mounts",NULL};
    if(confirmation&&nc_docker_confirmation_required(cfg,out))return -1;
    if(!nc_docker_keys(cfg,keys)||!nc_lxc_name_valid(name))return nc_lxc_error(out,"invalid_create_request");
    const char *commands[]={"lxc-create","lxc-info","lxc-start",NULL};
    for(int i=0;commands[i];i++)if(!nc_cmd_exists(commands[i]))return nc_lxc_error(out,"lxc_command_missing");
    if(access(NC_LXC_TEMPLATE_DIR "/lxc-local",X_OK))return nc_lxc_error(out,"lxc_local_template_missing");
    const char *booleans[]={"start_after_create","autostart","privileged_confirm",NULL};
    for(int i=0;booleans[i];i++){struct json_object *v=nc_docker_member(cfg,booleans[i]);if(v&&!json_object_is_type(v,json_type_boolean))return nc_lxc_error(out,"invalid_create_flags");}
    if(strcmp(nc_json_str_def(cfg,"network_mode","dhcp"),"dhcp"))return nc_lxc_error(out,"lxc_guest_static_address_unsupported");
    if(nc_lxc_bridge(nc_json_str_def(cfg,"bridge",""),out))return -1;
    struct json_object *ref=json_object_new_object(),*source_ref=nc_docker_member(cfg,"storage_ref"),*resources=json_object_new_object(),*templates=NULL;
    int rc=-1;char root[PATH_MAX],directory[PATH_MAX];struct stat st;struct statvfs fs;
    if(source_ref&&json_object_is_type(source_ref,json_type_object)){
        json_object_object_foreach(source_ref,key,value){json_object_object_add(ref,key,json_object_get(value));}
    }
    if(nc_lxc_root_admit(ref,root,out,1))goto done;
    if(snprintf(directory,sizeof(directory),"%s/%s",root,name)>=(int)sizeof(directory)){nc_lxc_error(out,"lxc_path_too_long");goto done;}
    if(!lstat(directory,&st)||errno!=ENOENT){nc_lxc_error(out,"lxc_name_exists");goto done;}
    struct json_object *roots=nc_lxc_roots();
    for(size_t i=0;i<json_object_array_length(roots);i++){
        char other[PATH_MAX];const char *path=json_object_get_string(json_object_array_get_idx(roots,i));
        if(snprintf(other,sizeof(other),"%s/%s",path,name)>=(int)sizeof(other)||!lstat(other,&st)){json_object_put(roots);nc_lxc_error(out,"lxc_name_exists");goto done;}
    }
    json_object_put(roots);
    if(statvfs(root,&fs)||(uint64_t)fs.f_bavail*fs.f_frsize<UINT64_C(268435456)){nc_lxc_error(out,"lxc_storage_insufficient");goto done;}
    json_object_object_add(resources,"memory_bytes",nc_docker_member(cfg,"memory_bytes")?json_object_get(nc_docker_member(cfg,"memory_bytes")):json_object_new_int64(134217728));
    json_object_object_add(resources,"cpu_weight",nc_docker_member(cfg,"cpu_weight")?json_object_get(nc_docker_member(cfg,"cpu_weight")):json_object_new_int(100));
    const char *startup[]={"autostart","start_order","start_delay",NULL};
    for(int i=0;startup[i];i++){
        struct json_object *v=nc_docker_member(cfg,startup[i]);
        json_object_object_add(resources,startup[i],v?json_object_get(v):i?json_object_new_int(0):json_object_new_boolean(0));
    }
    if(nc_lxc_document_validate_fields(resources,out))goto done;
    const char *privilege=nc_json_str_def(cfg,"privilege","unprivileged");unsigned long uid=0,gid=0;
    if(!strcmp(privilege,"unprivileged")){
        if(access("/proc/self/ns/user",F_OK)||nc_lxc_subid(NC_LXC_SUBUID,&uid)||nc_lxc_subid(NC_LXC_SUBGID,&gid)){nc_lxc_error(out,"lxc_userns_mapping_unavailable");goto done;}
    }else if(strcmp(privilege,"privileged")){nc_lxc_error(out,"invalid_privilege_mode");goto done;}
    else if(!nc_json_bool_def(cfg,"privileged_confirm",0)){nc_lxc_error(out,"privileged_confirmation_required");goto done;}
    struct json_object *mounts=nc_docker_member(cfg,"mounts"),*normalized=json_object_new_array();
    if(mounts&&(!json_object_is_type(mounts,json_type_array)||json_object_array_length(mounts)>8)){json_object_put(normalized);nc_lxc_error(out,"invalid_mounts");goto done;}
    for(size_t i=0;mounts&&i<json_object_array_length(mounts);i++){
        struct json_object *m=json_object_array_get_idx(mounts,i);const char *const mount_keys[]={"source","target","read_only",NULL};
        const char *target=nc_json_str_def(m,"target","");struct json_object *readonly=nc_docker_member(m,"read_only");
        if(!nc_docker_keys(m,mount_keys)||target[0]!='/'||!target[1]||strlen(target)>255||strstr(target,"..")||strchr(target,'\n')||strchr(target,'\r')||!readonly||!json_object_is_type(readonly,json_type_boolean)){
            json_object_put(normalized);nc_lxc_error(out,"invalid_mount");goto done;
        }
        for(size_t j=0;j<i;j++)if(!strcmp(target,nc_json_str_def(json_object_array_get_idx(normalized,j),"target",""))){json_object_put(normalized);nc_lxc_error(out,"duplicate_mount_target");goto done;}
        struct json_object *source=nc_docker_member(m,"source"),*copy=json_object_new_object();char canonical[PATH_MAX];
        if(source&&json_object_is_type(source,json_type_object)){
            json_object_object_foreach(source,key,value){json_object_object_add(copy,key,json_object_get(value));}
        }
        if(nc_lxc_root_admit(copy,canonical,out,!json_object_get_boolean(readonly))){json_object_put(copy);json_object_put(normalized);goto done;}
        struct json_object *item=json_object_new_object();json_object_object_add(item,"source",copy);nc_lxc_string(item,"target",target);nc_lxc_bool(item,"read_only",json_object_get_boolean(readonly));json_object_array_add(normalized,item);
    }
    json_object_object_add(plan,"mounts",normalized);
    templates=jmx_lxc_templates_get();struct json_object *data=nc_docker_member(templates,"data"),*catalog=nc_docker_member(data,"catalog"),*selected=NULL;
    if(!nc_json_bool_def(data,"ok",0)){nc_lxc_error(out,nc_json_str_def(data,"error","template_source_unavailable"));goto done;}
    for(size_t i=0;catalog&&i<json_object_array_length(catalog);i++){
        struct json_object *row=json_object_array_get_idx(catalog,i);
        if(!strcmp(nc_json_str_def(row,"id",""),nc_json_str_def(cfg,"template_id",""))&&!strcmp(nc_json_str_def(row,"build",""),nc_json_str_def(cfg,"build",""))){selected=row;break;}
    }
    if(!selected){nc_lxc_error(out,"template_changed_or_unavailable");goto done;}
    if(!nc_json_bool_def(selected,"compatible",0)){nc_lxc_error(out,"template_architecture_mismatch");goto done;}
    nc_lxc_string(plan,"name",name);nc_lxc_string(plan,"action","create");nc_lxc_string(plan,"lxcpath",root);json_object_object_add(plan,"storage_ref",json_object_get(ref));
    nc_lxc_string(plan,"template_id",nc_json_str_def(selected,"id",""));nc_lxc_string(plan,"build",nc_json_str_def(selected,"build",""));
    nc_lxc_string(plan,"bridge",nc_json_str_def(cfg,"bridge",""));nc_lxc_string(plan,"network_mode","dhcp");nc_lxc_string(plan,"privilege",privilege);
    nc_lxc_bool(plan,"privileged_confirm",!strcmp(privilege,"privileged"));nc_lxc_bool(plan,"start_after_create",nc_json_bool_def(cfg,"start_after_create",0));nc_lxc_bool(plan,"autostart",nc_json_bool_def(resources,"autostart",0));nc_lxc_bool(plan,"confirm",1);
    json_object_object_add(plan,"start_order",json_object_get(nc_docker_member(resources,"start_order")));json_object_object_add(plan,"start_delay",json_object_get(nc_docker_member(resources,"start_delay")));
    json_object_object_add(plan,"memory_bytes",json_object_get(nc_docker_member(resources,"memory_bytes")));json_object_object_add(plan,"cpu_weight",json_object_get(nc_docker_member(resources,"cpu_weight")));
    json_object_object_add(plan,"uid_base",json_object_new_int64(uid));json_object_object_add(plan,"gid_base",json_object_new_int64(gid));
    nc_lxc_string(plan,"rootfs_url",nc_json_str_def(selected,"rootfs_url",""));nc_lxc_string(plan,"metadata_url",nc_json_str_def(selected,"metadata_url",""));
    rc=0;
done:
    json_object_put(ref);json_object_put(resources);json_object_put(templates);return rc;
}

static int nc_lxc_create_submit(const char *name,struct json_object *cfg,struct json_object *out,int preview)
{
    struct json_object *plan=json_object_new_object();int rc=-1;char target[256];
    if(nc_lxc_create_plan(name,cfg,plan,out,!preview))goto done;
    if(preview){nc_lxc_bool(out,"ok",1);json_object_object_add(out,"plan",json_object_get(plan));nc_lxc_bool(out,"will_start",nc_json_bool_def(plan,"start_after_create",0));rc=0;goto done;}
    if(snprintf(target,sizeof(target),"%s/%s",nc_json_str_def(plan,"lxcpath",""),name)>=(int)sizeof(target)){nc_lxc_error(out,"lxc_path_too_long");goto done;}
    rc=nc_container_job_submit("lxc_create",target,json_object_to_json_string_ext(plan,JSON_C_TO_STRING_PLAIN),out);
done:
    json_object_put(plan);return rc;
}

struct nc_lxc_download {FILE *file;size_t bytes,limit;sqlite3 *jobs;const char *id;struct json_object *result;int64_t reported;};
static size_t nc_lxc_download_write(char *data,size_t size,size_t count,void *arg)
{
    struct nc_lxc_download *d=arg;size_t n=size*count;
    if(n>d->limit-d->bytes)return 0;
    size_t written=fwrite(data,1,n,d->file);d->bytes+=written;
    if(nc_now_s()!=d->reported){d->reported=nc_now_s();json_object_object_add(d->result,"download_bytes",json_object_new_int64(d->bytes));nc_lxc_job_stage(d->jobs,d->id,"download",d->result);}
    return written;
}

static int nc_lxc_download_file(const char *url,const char *path,size_t limit,sqlite3 *jobs,const char *id,struct json_object *result)
{
    struct nc_lxc_download d={.limit=limit,.jobs=jobs,.id=id,.result=result};
    int fd=open(path,O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC,0600);if(fd<0)return nc_lxc_error(result,"lxc_download_storage_failed");
    d.file=fdopen(fd,"wb");if(!d.file){close(fd);unlink(path);return nc_lxc_error(result,"lxc_download_storage_failed");}
    CURL *curl=curl_easy_init();long status=0;CURLcode code=CURLE_FAILED_INIT;
    if(curl){
        curl_easy_setopt(curl,CURLOPT_URL,url);
#if LIBCURL_VERSION_NUM >= 0x075500
        curl_easy_setopt(curl,CURLOPT_PROTOCOLS_STR,"https");curl_easy_setopt(curl,CURLOPT_REDIR_PROTOCOLS_STR,"https");
#else
        curl_easy_setopt(curl,CURLOPT_PROTOCOLS,(long)CURLPROTO_HTTPS);curl_easy_setopt(curl,CURLOPT_REDIR_PROTOCOLS,(long)CURLPROTO_HTTPS);
#endif
        curl_easy_setopt(curl,CURLOPT_SSL_VERIFYPEER,1L);curl_easy_setopt(curl,CURLOPT_SSL_VERIFYHOST,2L);curl_easy_setopt(curl,CURLOPT_FOLLOWLOCATION,1L);curl_easy_setopt(curl,CURLOPT_MAXREDIRS,3L);
        curl_easy_setopt(curl,CURLOPT_CONNECTTIMEOUT,10L);curl_easy_setopt(curl,CURLOPT_TIMEOUT,180L);curl_easy_setopt(curl,CURLOPT_NOSIGNAL,1L);
        curl_easy_setopt(curl,CURLOPT_USERAGENT,"lxc/7.0.0 compat:5");curl_easy_setopt(curl,CURLOPT_WRITEFUNCTION,nc_lxc_download_write);curl_easy_setopt(curl,CURLOPT_WRITEDATA,&d);
        code=curl_easy_perform(curl);curl_easy_getinfo(curl,CURLINFO_RESPONSE_CODE,&status);curl_easy_cleanup(curl);
    }
    int io=fflush(d.file)||fsync(fd);if(fclose(d.file))io=1;
    if(code!=CURLE_OK||status!=200||io||!d.bytes){unlink(path);return nc_lxc_error(result,d.bytes>=limit?"template_download_too_large":io?"lxc_download_storage_failed":"template_download_failed");}
    json_object_object_add(result,"download_bytes",json_object_new_int64(d.bytes));json_object_object_add(result,"download_total_bytes",NULL);return 0;
}

static int nc_lxc_mount_token(FILE *file,const char *text)
{
    for(const unsigned char *p=(const unsigned char *)text;*p;p++){
        if(isspace(*p)||*p=='\\'){if(fprintf(file,"\\%03o",*p)<0)return -1;}
        else if(fputc(*p,file)==EOF)return -1;
    }
    return 0;
}

static int nc_lxc_create_config(const char *path,struct json_object *request)
{
    char *base=nc_lxc_read_text(NC_LXC_DEFAULT_CONFIG,32768);
    if(!base&&errno!=ENOENT)return -1;
    FILE *file=fopen(path,"wx");if(!file){free(base);return -1;}
    int rc=-1;
    if(base&&fputs(base,file)==EOF)goto done;
    if(fprintf(file,"\nlxc.idmap =\nlxc.net =\nlxc.net.0.type = veth\nlxc.net.0.link = %s\nlxc.net.0.name = eth0\nlxc.net.0.flags = up\nlxc.mount.entry =\nlxc.log.file = %s/%s/lxc.log\nlxc.log.level = INFO\n",nc_json_str_def(request,"bridge",""),nc_json_str_def(request,"lxcpath",""),nc_json_str_def(request,"name",""))<0)goto done;
    if(!strcmp(nc_json_str_def(request,"privilege",""),"unprivileged")&&fprintf(file,"lxc.idmap = u 0 %lld 65536\nlxc.idmap = g 0 %lld 65536\n",(long long)json_object_get_int64(nc_docker_member(request,"uid_base")),(long long)json_object_get_int64(nc_docker_member(request,"gid_base")))<0)goto done;
    int64_t memory=json_object_get_int64(nc_docker_member(request,"memory_bytes"));
    if(memory){if(fprintf(file,"lxc.cgroup2.memory.max = %lld\n",(long long)memory)<0)goto done;}
    else if(fputs("lxc.cgroup2.memory.max = max\n",file)==EOF)goto done;
    if(fprintf(file,"lxc.cgroup2.cpu.weight = %lld\n",(long long)json_object_get_int64(nc_docker_member(request,"cpu_weight")))<0)goto done;
    struct json_object *mounts=nc_docker_member(request,"mounts");
    for(size_t i=0;mounts&&i<json_object_array_length(mounts);i++){
        struct json_object *m=json_object_array_get_idx(mounts,i);
        if(fputs("lxc.mount.entry = ",file)==EOF||nc_lxc_mount_token(file,nc_json_str_def(nc_docker_member(m,"source"),"path",""))||fputc(' ',file)==EOF||nc_lxc_mount_token(file,nc_json_str_def(m,"target","")+1)||fprintf(file," none bind,%s,create=dir 0 0\n",nc_json_bool_def(m,"read_only",0)?"ro":"rw")<0)goto done;
    }
    if(fprintf(file,"lxc.start.auto = %d\nlxc.start.order = %d\nlxc.start.delay = %d\n",nc_json_bool_def(request,"autostart",0),nc_json_int_def(request,"start_order",0),nc_json_int_def(request,"start_delay",0))<0)goto done;
    struct json_object *options=json_object_new_object();nc_lxc_string(options,"bridge",nc_json_str_def(request,"bridge",""));json_object_object_add(options,"mounts",json_object_get(mounts));
    int option_written=fprintf(file,"# dwrt.lxc.options = %s\n",json_object_to_json_string_ext(options,JSON_C_TO_STRING_PLAIN));json_object_put(options);if(option_written<0)goto done;
    if(fflush(file)||fsync(fileno(file)))goto done;
    rc=0;
done:
    if(fclose(file))rc=-1;
    free(base);return rc;
}

static int nc_lxc_created_record(const char *name,struct json_object *request,struct json_object *out)
{
    char root[PATH_MAX],identity[80],path[PATH_MAX];sqlite3 *db=NULL;sqlite3_stmt *st=NULL;char *text=NULL;int rc=-1,transaction=0;
    if(nc_lxc_identity(name,root,sizeof(root),identity,sizeof(identity),out)||snprintf(path,sizeof(path),"%s/%s/config",root,name)>=(int)sizeof(path))return -1;
    text=nc_lxc_read_text(path,32768);if(!text||nc_lxc_document_db(&db))goto done;
    if(sqlite3_exec(db,"CREATE TABLE IF NOT EXISTS lxc_origin(path TEXT PRIMARY KEY,source_json TEXT NOT NULL)",NULL,NULL,NULL)!=SQLITE_OK)goto done;
    if(sqlite3_exec(db,"BEGIN IMMEDIATE",NULL,NULL,NULL)!=SQLITE_OK)goto done;
    transaction=1;
    if(sqlite3_prepare_v2(db,"INSERT INTO lxc_config_document(path,name,identity,revision,desired,applied,state,updated_at) VALUES(?1,?2,?3,1,?4,?4,'idle',?5) ON CONFLICT(path) DO UPDATE SET identity=excluded.identity,revision=lxc_config_document.revision+1,desired=excluded.desired,applied=excluded.applied,state='idle',previous='',was_running=0,last_error='',updated_at=excluded.updated_at",-1,&st,NULL)!=SQLITE_OK)goto done;
    sqlite3_bind_text(st,1,path,-1,SQLITE_TRANSIENT);sqlite3_bind_text(st,2,name,-1,SQLITE_TRANSIENT);sqlite3_bind_text(st,3,identity,-1,SQLITE_TRANSIENT);sqlite3_bind_text(st,4,text,-1,SQLITE_TRANSIENT);sqlite3_bind_int64(st,5,nc_now_s());
    if(sqlite3_step(st)!=SQLITE_DONE)goto done;
    sqlite3_finalize(st);st=NULL;
    if(sqlite3_prepare_v2(db,"INSERT INTO lxc_origin(path,source_json) VALUES(?1,?2) ON CONFLICT(path) DO UPDATE SET source_json=excluded.source_json",-1,&st,NULL)!=SQLITE_OK)goto done;
    sqlite3_bind_text(st,1,path,-1,SQLITE_TRANSIENT);sqlite3_bind_text(st,2,json_object_to_json_string_ext(request,JSON_C_TO_STRING_PLAIN),-1,SQLITE_TRANSIENT);
    if(sqlite3_step(st)==SQLITE_DONE&&sqlite3_exec(db,"COMMIT",NULL,NULL,NULL)==SQLITE_OK){transaction=0;rc=0;}
done:
    if(st)sqlite3_finalize(st);
    if(transaction)sqlite3_exec(db,"ROLLBACK",NULL,NULL,NULL);
    if(db)sqlite3_close(db);
    free(text);if(rc)nc_lxc_error(out,"lxc_config_storage_failed");return rc;
}

static int nc_lxc_create_execute(sqlite3 *jobs,const char *id,const char *target,struct json_object *request,struct nc_exec_result *capture,struct json_object *out)
{
    struct json_object *input=json_object_new_object(),*plan=json_object_new_object();sqlite3 *db=NULL;
    const char *name=nc_json_str_def(request,"name","");char expected[256],work[PATH_MAX]="",metadata[PATH_MAX]="",rootfs[PATH_MAX]="",config[PATH_MAX]="";int rc=125;
    json_object_object_foreach(request,key,value){if(strcmp(key,"lxcpath")&&strcmp(key,"rootfs_url")&&strcmp(key,"metadata_url")&&strcmp(key,"uid_base")&&strcmp(key,"gid_base"))json_object_object_add(input,key,json_object_get(value));}
    if(nc_lxc_create_plan(name,input,plan,out,1))goto done;
    if(strcmp(json_object_to_json_string_ext(plan,JSON_C_TO_STRING_PLAIN),json_object_to_json_string_ext(request,JSON_C_TO_STRING_PLAIN))){nc_lxc_error(out,"lxc_create_plan_changed");goto done;}
    const char *root=nc_json_str_def(plan,"lxcpath","");
    if(snprintf(expected,sizeof(expected),"%s/%s",root,name)>=(int)sizeof(expected)||strcmp(expected,target)){nc_lxc_error(out,"lxc_root_changed");goto done;}
    nc_lxc_string(out,"name",name);nc_lxc_string(out,"lxcpath",root);nc_lxc_bool(out,"remaining_object",0);nc_lxc_string(out,"privilege",nc_json_str_def(plan,"privilege",""));
    if(nc_lxc_document_db(&db)||nc_lxc_root_remember(db,root)){nc_lxc_error(out,"lxc_config_storage_failed");goto done;}
    sqlite3_close(db);db=NULL;
    if(snprintf(work,sizeof(work),"%s/.dwrt-create-XXXXXX",root)>=(int)sizeof(work)||!mkdtemp(work)){work[0]=0;nc_lxc_error(out,"lxc_download_storage_failed");goto done;}
    nc_lxc_string(out,"staging_path",work);nc_lxc_bool(out,"staging_present",1);
    if(snprintf(metadata,sizeof(metadata),"%s/meta.tar.xz",work)>=(int)sizeof(metadata)||snprintf(rootfs,sizeof(rootfs),"%s/rootfs.tar.xz",work)>=(int)sizeof(rootfs)||snprintf(config,sizeof(config),"%s/create.conf",work)>=(int)sizeof(config))goto done;
    nc_lxc_string(out,"download_file","metadata");if(nc_lxc_job_stage(jobs,id,"download",out)||nc_lxc_download_file(nc_json_str_def(plan,"metadata_url",""),metadata,1048576,jobs,id,out))goto done;
    nc_lxc_string(out,"download_file","rootfs");if(nc_lxc_download_file(nc_json_str_def(plan,"rootfs_url",""),rootfs,134217728,jobs,id,out))goto done;
    if(nc_lxc_create_config(config,plan)){nc_lxc_error(out,"lxc_config_write_failed");goto done;}
    if(nc_lxc_job_stage(jobs,id,"create",out))goto done;
    nc_lxc_string(out,"remaining_path",expected);
    if(nc_lxc_job_stage(jobs,id,"create",out))goto done;
    const char *argv[]={"lxc-create","-P",root,"-n",name,"-B","dir","-f",config,"-t",NC_LXC_TEMPLATE_DIR "/lxc-local","--","--metadata",metadata,"--fstree",rootfs,NULL};
    rc=nc_exec_argv_capture_ex(argv,180,NC_CONTAINER_OUTPUT_MAX,capture,0);
    struct stat st;int exists=!lstat(expected,&st);nc_lxc_bool(out,"remaining_object",exists);
    if(exists){char identity[80];snprintf(identity,sizeof(identity),"%llu:%llu",(unsigned long long)st.st_dev,(unsigned long long)st.st_ino);nc_lxc_string(out,"identity",identity);nc_lxc_string(out,"remaining_path",expected);}
    if(rc){nc_lxc_error(out,"lxc_create_failed");goto done;}
    nc_lxc_bool(out,"created",1);
    if(nc_lxc_created_record(name,plan,out)){rc=125;goto done;}
    if(nc_json_bool_def(plan,"start_after_create",0)){
        if(nc_lxc_job_stage(jobs,id,"start",out)){rc=125;goto done;}
        const char *start[]={"lxc-start","-P",root,"-n",name,"-d",NULL};nc_exec_result_free(capture);
        rc=nc_exec_argv_capture_ex(start,40,NC_CONTAINER_OUTPUT_MAX,capture,0);if(rc){nc_lxc_error(out,"lxc_create_start_failed");goto done;}
    }
    char state[24];if(nc_lxc_state(root,name,state,sizeof(state),out)||strcmp(state,nc_json_bool_def(plan,"start_after_create",0)?"RUNNING":"STOPPED")){rc=125;nc_lxc_error(out,"lxc_state_not_confirmed");goto done;}
    nc_lxc_bool(out,"ok",1);nc_lxc_bool(out,"started",!strcmp(state,"RUNNING"));nc_lxc_string(out,"state",state);nc_lxc_string(out,"stage","verified");nc_lxc_bool(out,"readback_required",0);rc=0;
done:
    if(*metadata)unlink(metadata);
    if(*rootfs)unlink(rootfs);
    if(*config)unlink(config);
    if(*work)nc_lxc_bool(out,"staging_present",rmdir(work)!=0);
    if(db)sqlite3_close(db);
    json_object_put(input);json_object_put(plan);return rc;
}
