/* Docker workbench workflows. Kept in the existing core/SQLite task system. */
#include <sys/statvfs.h>
#include "033_nc_docker_cleanup.inc"

static int nc_docker_compose_available(void)
{
    const char *const argv[]={"docker","compose","version","--short",NULL};
    struct nc_exec_result r={0};
    int rc=nc_exec_argv_capture(argv,5,256,&r);
    nc_exec_result_free(&r);
    return rc==0;
}

static int nc_docker_compose_build_available(void)
{
    const char *const argv[]={"docker","buildx","version",NULL};
    struct nc_exec_result r={0};int rc=nc_exec_argv_capture(argv,5,256,&r);
    nc_exec_result_free(&r);return rc==0;
}

static int nc_docker_workflow_kind(const char *kind)
{
    return kind && (!strcmp(kind,"docker_migration") || !strcmp(kind,"docker_config") || !strcmp(kind,"docker_cleanup") || !strcmp(kind,"image_load") || !strcmp(kind,"compose_action") ||
        !strcmp(kind,"container_clone") || !strcmp(kind,"container_recreate") || !strcmp(kind,"container_recover") || !strcmp(kind,"network_recreate") || !strcmp(kind,"network_recover"));
}

/* File identity is frozen at submission and rechecked by the worker. The open
 * descriptor, not an unchecked browser path, is passed to the Docker child. */
static int nc_docker_import_open(struct json_object *cfg,
                                 struct storage_files_stream *stream,
                                 struct json_object *out)
{
    struct json_object *ref=nc_docker_member(cfg,"file_ref");
    const char *const keys[]={"root_id","path","size_bytes","inode","modified_unix",NULL};
    if(!nc_docker_keys(ref,keys) || !nc_docker_string(nc_docker_member(ref,"root_id"),47) ||
       !nc_docker_string(nc_docker_member(ref,"path"),PATH_MAX-1))
        return nc_docker_create_error(out,"invalid_file_reference","file_ref","file_service_reference_required");
    const char *reason=NULL;
    if(storage_files_open_stream(nc_json_str_def(ref,"root_id",""),nc_json_str_def(ref,"path",""),stream,&reason))
        return nc_docker_create_error(out,"file_unavailable","file_ref",reason?reason:"open_failed");
    const char *fields[]={"size_bytes","inode","modified_unix"};
    uint64_t values[]={stream->size_bytes,stream->inode,(uint64_t)stream->modified_unix};
    for(int i=0;i<3;i++) {
        struct json_object *v=nc_docker_member(ref,fields[i]);
        if(v&&(!json_object_is_type(v,json_type_int)||(uint64_t)json_object_get_int64(v)!=values[i])) {
            close(stream->fd);stream->fd=-1;
            return nc_docker_create_error(out,"file_changed","file_ref","select_file_again");
        }
        json_object_object_add(ref,fields[i],json_object_new_int64((int64_t)values[i]));
    }
    return 0;
}

static int nc_docker_image_archive(struct json_object *cfg,
                                  struct storage_files_stream *stream,struct json_object *out)
{
    if(nc_docker_import_open(cfg,stream,out))return -1;
    unsigned char header[512];ssize_t got=pread(stream->fd,header,sizeof(header),0);
    const char *name=stream->basename;size_t n=strlen(name);
    int tar=n>4&&!strcmp(name+n-4,".tar"),gz=n>7&&!strcmp(name+n-7,".tar.gz");
    if(stream->size_bytes<512||got<512||
       !((tar&&!memcmp(header+257,"ustar",5))||(gz&&header[0]==0x1f&&header[1]==0x8b))) {
        close(stream->fd);stream->fd=-1;
        return nc_docker_create_error(out,"invalid_image_archive","file_ref","tar_or_tar_gz_required");
    }
    const char *const argv[]={"docker","info","--format","{{json .}}",NULL};
    struct json_object *info=nc_docker_read_json(argv,0,NULL);struct statvfs space;
    const char *root=nc_json_str_def(info,"DockerRootDir","");
    int known=*root&&statvfs(root,&space)==0;
    uint64_t free_bytes=known?(uint64_t)space.f_bavail*space.f_frsize:0;
    if(info)json_object_put(info);
    if(!known||stream->size_bytes>free_bytes) {
        close(stream->fd);stream->fd=-1;
        return nc_docker_create_error(out,known?"insufficient_storage":"storage_unavailable","file_ref","docker_data_root_free_space");
    }
    return 0;
}

static int nc_docker_workflow_schema(sqlite3 *db)
{
    return sqlite3_exec(db,
        "CREATE TABLE IF NOT EXISTS docker_compose_project("
        "id TEXT PRIMARY KEY,name TEXT NOT NULL,revision INTEGER NOT NULL,source TEXT NOT NULL,"
        "created_at INTEGER NOT NULL,updated_at INTEGER NOT NULL,deleted INTEGER NOT NULL DEFAULT 0);"
        "CREATE TABLE IF NOT EXISTS docker_compose_revision("
        "project_id TEXT NOT NULL,revision INTEGER NOT NULL,secret_id TEXT NOT NULL,"
        "PRIMARY KEY(project_id,revision));"
        "CREATE TABLE IF NOT EXISTS docker_compose_directory("
        "project_id TEXT NOT NULL,revision INTEGER NOT NULL,reference_json TEXT NOT NULL,"
        "PRIMARY KEY(project_id,revision));",NULL,NULL,NULL)==SQLITE_OK?0:-1;
}

static int nc_docker_compose_id(const char *id)
{
    if(!id||strlen(id)!=36||strncmp(id,"cmp-",4))return 0;
    for(int i=4;i<36;i++)if(!isxdigit((unsigned char)id[i]))return 0;
    return 1;
}

static int nc_docker_compose_random_id(char id[37])
{
    unsigned char value[16];int fd=open("/dev/urandom",O_RDONLY|O_CLOEXEC);
    ssize_t n=fd<0?-1:read(fd,value,sizeof(value));if(fd>=0)close(fd);
    if(n!=sizeof(value))return -1;
    memcpy(id,"cmp-",4);
    for(int i=0;i<16;i++)snprintf(id+4+i*2,3,"%02x",value[i]);
    return 0;
}

/* The original YAML is encrypted in the platform vault. A short-lived private
 * file is only materialized for validation/execution. It is never a second
 * persistent configuration authority or exposed in ordinary task output. */
struct nc_docker_compose_file { char dir[128]; char path[160]; };
static void nc_docker_compose_file_close(struct nc_docker_compose_file *f)
{
    if(f->path[0])unlink(f->path);
    if(f->dir[0])rmdir(f->dir);
}
static int nc_docker_compose_file_open(const char *yaml,struct nc_docker_compose_file *f)
{
    snprintf(f->dir,sizeof(f->dir),"/tmp/dwrt-compose-XXXXXX");
    if(!mkdtemp(f->dir))return -1;
    snprintf(f->path,sizeof(f->path),"%s/compose.yaml",f->dir);
    int fd=open(f->path,O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC,0600);
    size_t len=strlen(yaml),offset=0;
    if(fd<0){nc_docker_compose_file_close(f);return -1;}
    while(offset<len) {
        ssize_t n=write(fd,yaml+offset,len-offset);
        if(n<0&&errno==EINTR)continue;
        if(n<=0)break;
        offset+=(size_t)n;
    }
    int rc=offset==len&&fsync(fd)==0?0:-1;
    if(close(fd))rc=-1;
    if(rc)nc_docker_compose_file_close(f);
    return rc;
}

/* A project directory is a reference admitted by storage-files, with identity
 * retained per configuration revision. The YAML remains the saved authority. */
static int nc_docker_compose_directory(struct json_object *ref,char path[PATH_MAX],
                                       struct json_object *out)
{
    path[0]=0;
    if(!ref||json_object_is_type(ref,json_type_null))return 0;
    const char *const keys[]={"root_id","path","device","inode",NULL};
    if(!nc_docker_keys(ref,keys)||!nc_docker_string(nc_docker_member(ref,"path"),PATH_MAX-1))
        return nc_docker_create_error(out,"invalid_project_directory","directory_ref","storage_directory_required");
    const char *reason=NULL;
    int fd=storage_files_open_dir(nc_json_str_def(ref,"root_id",""),nc_json_str_def(ref,"path",""),0,path,PATH_MAX,&reason);
    struct stat st;
    if(fd<0||fstat(fd,&st)) {
        if(fd>=0)close(fd);
        return nc_docker_create_error(out,"project_directory_unavailable","directory_ref",reason?reason:"stat_failed");
    }
    close(fd);
    const char *names[]={"device","inode"};uint64_t values[]={(uint64_t)st.st_dev,(uint64_t)st.st_ino};
    for(int i=0;i<2;i++) {
        struct json_object *value=nc_docker_member(ref,names[i]);
        if(value&&(!json_object_is_type(value,json_type_int)||(uint64_t)json_object_get_int64(value)!=values[i]))
            return nc_docker_create_error(out,"project_directory_changed","directory_ref","select_directory_again");
        json_object_object_add(ref,names[i],json_object_new_int64((int64_t)values[i]));
    }
    return 0;
}

static int nc_docker_compose_path(const char *path,int directory,int writing,
                                  const char *field,struct json_object *out)
{
    const char *reason=NULL;int fd=-1;char canonical[PATH_MAX];
    if(nc_docker_path(path)) {
        if(directory)fd=storage_files_open_dir("",path,writing,canonical,sizeof(canonical),&reason);
        else {struct storage_files_stream stream={.fd=-1};
            if(!storage_files_open_stream("",path,&stream,&reason))fd=stream.fd;}
    }
    if(fd<0)return nc_docker_create_error(out,"compose_file_unavailable",field,reason?reason:"local_storage_path_required");
    close(fd);return 0;
}

/* Compose resolves YAML, anchors and relative paths. Inspect the resolved model
 * before allowing a build or service action; execute that same model. This also
 * keeps external-file paths from being reinterpreted relative to /tmp. */
static struct json_object *nc_docker_compose_model(const char *yaml,struct json_object *directory,
                                                  const char *project,struct json_object *out)
{
    struct nc_docker_compose_file f={0};char workdir[PATH_MAX];
    if(!yaml||!*yaml||strlen(yaml)>96*1024){nc_docker_invalid(out,"invalid_compose_yaml_size");return NULL;}
    if(nc_docker_compose_directory(directory,workdir,out))return NULL;
    if(nc_docker_compose_file_open(yaml,&f)){nc_docker_invalid(out,"compose_tempfile_failed");return NULL;}
    const char *argv[22]={"docker","compose","--env-file","/dev/null","-p",project,"-f",f.path};int n=8;
    if(*workdir){argv[n++]="--project-directory";argv[n++]=workdir;}
    argv[n++]="config";argv[n++]="--format";argv[n++]="json";argv[n++]="--no-env-resolution";argv[n]=NULL;
    struct json_object *model=nc_docker_read_json(argv,0,NULL);
    nc_docker_compose_file_close(&f);
    if(!model){nc_docker_create_error(out,"invalid_compose_yaml","yaml","compose_config_validation_failed");return NULL;}
    struct json_object *services=nc_docker_member(model,"services");int rc=0;
    if(!services||!json_object_is_type(services,json_type_object)||!json_object_object_length(services))rc=-1;
    if(services&&json_object_is_type(services,json_type_object)) {
        json_object_object_foreach(services,key,service) {
            (void)key;
            if(nc_json_bool_def(service,"privileged",0)||!strcmp(nc_json_str_def(service,"network_mode",""),"host")||
               !strcmp(nc_json_str_def(service,"pid",""),"host")||nc_docker_member(service,"devices")||nc_docker_member(service,"cap_add")) {
                nc_docker_create_error(out,"capability_disabled","yaml","privileged_container_unsupported");rc=-1;break;
            }
            struct json_object *build=nc_docker_member(service,"build");
            if(build) {
                const char *context=nc_json_str_def(build,"context","");
                if(!*workdir){nc_docker_create_error(out,"capability_disabled","build","compose_project_directory_required");rc=-1;}
                else if(nc_docker_compose_path(context,1,0,"build.context",out))rc=-1;
                if(nc_docker_member(build,"additional_contexts")||nc_docker_member(build,"ssh")||nc_docker_member(build,"entitlements")||nc_docker_member(build,"secrets")) {
                    nc_docker_create_error(out,"capability_disabled","build","build_external_sources_unsupported");rc=-1;
                }
                if(!nc_docker_member(build,"dockerfile_inline")) {
                    const char *dockerfile=nc_json_str_def(build,"dockerfile","Dockerfile");char path[PATH_MAX];
                    int len=snprintf(path,sizeof(path),"%s%s%s",dockerfile[0]=='/'?"":context,dockerfile[0]=='/'?"":"/",dockerfile);
                    if(len<0||(size_t)len>=sizeof(path)||nc_docker_compose_path(path,0,0,"build.dockerfile",out))rc=-1;
                }
            }
            struct json_object *env=nc_docker_member(service,"env_file");
            for(size_t i=0;env&&i<json_object_array_length(env);i++) {
                struct json_object *item=json_object_array_get_idx(env,i);
                const char *path=json_object_is_type(item,json_type_string)?json_object_get_string(item):nc_json_str_def(item,"path","");
                if(nc_docker_compose_path(path,0,0,"env_file",out))rc=-1;
            }
            struct json_object *volumes=nc_docker_member(service,"volumes");
            for(size_t i=0;volumes&&i<json_object_array_length(volumes);i++) {
                struct json_object *v=json_object_array_get_idx(volumes,i);
                if(!strcmp(nc_json_str_def(v,"type",""),"bind")&&
                   nc_docker_compose_path(nc_json_str_def(v,"source",""),1,!nc_json_bool_def(v,"read_only",0),"volumes",out))rc=-1;
            }
        }
    }
    const char *groups[]={"secrets","configs",NULL};
    for(int i=0;groups[i];i++) {
        struct json_object *group=nc_docker_member(model,groups[i]);
        if(group&&json_object_is_type(group,json_type_object)) {
            json_object_object_foreach(group,k,v) {
                (void)k;
                if(nc_docker_member(v,"file")&&nc_docker_compose_path(nc_json_str_def(v,"file",""),0,0,groups[i],out))rc=-1;
            }
        }
    }
    if(rc){json_object_put(model);if(!nc_docker_member(out,"error"))nc_docker_invalid(out,"compose_services_required");return NULL;}
    return model;
}

static int nc_docker_compose_validate(const char *yaml,struct json_object *directory,struct json_object *out)
{
    struct json_object *model=nc_docker_compose_model(yaml,directory,"dwrt-validate",out);
    if(!model)return -1;
    json_object_put(model);return 0;
}

static struct json_object *nc_docker_compose_meta(sqlite3 *db,const char *id)
{
    sqlite3_stmt *st=NULL;struct json_object *o=NULL;
    if(sqlite3_prepare_v2(db,"SELECT id,name,revision,source,created_at,updated_at FROM docker_compose_project WHERE id=?1 AND deleted=0",-1,&st,NULL)!=SQLITE_OK)return NULL;
    sqlite3_bind_text(st,1,id,-1,SQLITE_TRANSIENT);
    if(sqlite3_step(st)==SQLITE_ROW) {
        o=json_object_new_object();
        const char *keys[]={"id","name","revision","source","created_at","updated_at"};
        for(int i=0;i<6;i++)json_object_object_add(o,keys[i],(i==2||i>=4)?json_object_new_int64(sqlite3_column_int64(st,i)):json_object_new_string((const char *)sqlite3_column_text(st,i)));
        json_object_object_add(o,"engine_project",json_object_new_string(id));
        json_object_object_add(o,"config_location",json_object_new_string("core-db:docker_compose_revision/ac_secrets"));
        json_object_object_add(o,"managed",json_object_new_boolean(1));
    }
    sqlite3_finalize(st);st=NULL;
    if(o&&sqlite3_prepare_v2(db,"SELECT reference_json FROM docker_compose_directory WHERE project_id=?1 AND revision=?2",-1,&st,NULL)==SQLITE_OK) {
        sqlite3_bind_text(st,1,id,-1,SQLITE_TRANSIENT);sqlite3_bind_int(st,2,nc_json_int_def(o,"revision",0));
        if(sqlite3_step(st)==SQLITE_ROW) {
            struct json_object *ref=json_tokener_parse((const char *)sqlite3_column_text(st,0));
            if(ref)json_object_object_add(o,"directory_ref",ref);
        }
    }
    if(st)sqlite3_finalize(st);
    return o;
}

static char *nc_docker_compose_yaml(sqlite3 *db,const char *id,int revision)
{
    sqlite3_stmt *st=NULL;struct ac_secrets *vault=NULL;unsigned char *clear=NULL;size_t len=0;char *yaml=NULL;
    if(ac_secrets_open(db,NC_CONTAINER_SECRET_KEY_PATH,&vault)!=AC_SECRETS_OK)return NULL;
    if(sqlite3_prepare_v2(db,"SELECT secret_id FROM docker_compose_revision WHERE project_id=?1 AND revision=?2",-1,&st,NULL)==SQLITE_OK) {
        sqlite3_bind_text(st,1,id,-1,SQLITE_TRANSIENT);sqlite3_bind_int(st,2,revision);
        if(sqlite3_step(st)==SQLITE_ROW&&ac_secrets_get(vault,(const char *)sqlite3_column_text(st,0),1,&clear,&len)==AC_SECRETS_OK&&len<=96*1024)yaml=strndup((const char *)clear,len);
    }
    if(st) { sqlite3_finalize(st); }
    ac_secrets_clear(clear,len);ac_secrets_close(vault);return yaml;
}

static int nc_docker_compose_busy(sqlite3 *db,const char *id)
{
    sqlite3_stmt *st=NULL;int busy=1;
    if(sqlite3_prepare_v2(db,"SELECT COUNT(*) FROM container_job WHERE kind='compose_action' AND target=?1 AND state IN ('queued','running')",-1,&st,NULL)==SQLITE_OK) {
        sqlite3_bind_text(st,1,id,-1,SQLITE_TRANSIENT);
        if(sqlite3_step(st)==SQLITE_ROW)busy=sqlite3_column_int(st,0)>0;
    }
    if(st) { sqlite3_finalize(st); }return busy;
}

static int nc_docker_compose_save(struct json_object *cfg,struct json_object *out)
{
    sqlite3 *db=NULL;sqlite3_stmt *st=NULL;struct ac_secrets *vault=NULL;
    struct json_object *meta=NULL;char id[37],secret[96],*imported=NULL;
    const char *yaml=nc_json_str_def(cfg,"yaml",""),*name=nc_json_str_def(cfg,"name","");
    const char *requested=nc_json_str_def(cfg,"id","");int existing=*requested!=0,revision=1,rc=-1;
    if(existing&&!nc_docker_compose_id(requested))return nc_docker_invalid(out,"invalid_project_id");
    if(!nc_docker_name_valid(name))return nc_docker_create_error(out,"invalid_project_name","name","docker_name_required");
    if(nc_docker_member(cfg,"file_ref")) {
        struct storage_files_stream file={.fd=-1};
        if(nc_docker_import_open(cfg,&file,out))return -1;
        if(!file.size_bytes||file.size_bytes>96*1024){close(file.fd);return nc_docker_invalid(out,"invalid_compose_yaml_size");}
        imported=calloc(1,file.size_bytes+1);
        ssize_t got=imported?read(file.fd,imported,file.size_bytes):-1;close(file.fd);
        if(got!=(ssize_t)file.size_bytes||strlen(imported)!=(size_t)got){free(imported);return nc_docker_invalid(out,"invalid_compose_file");}
        yaml=imported;
    }
    if(!nc_docker_compose_available()){nc_docker_invalid(out,"compose_not_installed");goto done;}
    struct json_object *directory=nc_docker_member(cfg,"directory_ref");
    if(imported&&!directory) {
        struct json_object *file=nc_docker_member(cfg,"file_ref");
        const char *path=nc_json_str_def(file,"path","");char parent[PATH_MAX];snprintf(parent,sizeof(parent),"%s",path);
        char *slash=strrchr(parent,'/');if(slash){if(slash==parent)slash[1]=0;else *slash=0;}
        directory=json_object_new_object();
        json_object_object_add(directory,"root_id",json_object_new_string(nc_json_str_def(file,"root_id","")));
        json_object_object_add(directory,"path",json_object_new_string(parent));json_object_object_add(cfg,"directory_ref",directory);
    }
    if(existing&&!directory) {
        sqlite3 *lookup=NULL;
        if(!nc_container_job_db_open(&lookup)&&!nc_docker_workflow_schema(lookup)) {
            struct json_object *old=nc_docker_compose_meta(lookup,requested);
            if(old){directory=nc_docker_member(old,"directory_ref");if(directory)json_object_object_add(cfg,"directory_ref",json_object_get(directory));json_object_put(old);}
        }
        if(lookup)sqlite3_close(lookup);
    }
    if(nc_docker_compose_validate(yaml,directory,out))goto done;
    if(nc_container_job_db_open(&db)||nc_docker_workflow_schema(db)||
       ac_secrets_schema_init(db)!=AC_SECRETS_OK||ac_secrets_open_or_create(db,NC_CONTAINER_SECRET_KEY_PATH,&vault)!=AC_SECRETS_OK)goto storage;
    if(sqlite3_exec(db,"BEGIN IMMEDIATE",NULL,NULL,NULL)!=SQLITE_OK)goto storage;
    if(existing) {
        snprintf(id,sizeof(id),"%s",requested);meta=nc_docker_compose_meta(db,id);
        if(!meta){nc_docker_invalid(out,"compose_project_not_found");goto rollback;}
        revision=nc_json_int_def(meta,"revision",0);
        if(!nc_docker_integer(nc_docker_member(cfg,"revision"),revision,revision)){nc_docker_invalid(out,"revision_conflict");goto rollback;}
        if(nc_docker_compose_busy(db,id)){nc_docker_invalid(out,"compose_project_busy");goto rollback;}
        revision++;
    } else if(nc_docker_compose_random_id(id))goto rollback;
    snprintf(secret,sizeof(secret),"compose-%s-%d",id,revision);
    if(ac_secrets_put(vault,secret,1,(const unsigned char *)yaml,strlen(yaml))!=AC_SECRETS_OK)goto rollback;
    if(sqlite3_prepare_v2(db,"INSERT INTO docker_compose_revision(project_id,revision,secret_id) VALUES(?1,?2,?3)",-1,&st,NULL)!=SQLITE_OK)goto rollback;
    sqlite3_bind_text(st,1,id,-1,SQLITE_TRANSIENT);sqlite3_bind_int(st,2,revision);sqlite3_bind_text(st,3,secret,-1,SQLITE_TRANSIENT);
    if(sqlite3_step(st)!=SQLITE_DONE)goto rollback;
    sqlite3_finalize(st);st=NULL;
    if(sqlite3_prepare_v2(db,existing?"UPDATE docker_compose_project SET name=?2,revision=?3,updated_at=?5 WHERE id=?1":"INSERT INTO docker_compose_project(id,name,revision,source,created_at,updated_at) VALUES(?1,?2,?3,?4,?5,?5)",-1,&st,NULL)!=SQLITE_OK)goto rollback;
    sqlite3_bind_text(st,1,id,-1,SQLITE_TRANSIENT);sqlite3_bind_text(st,2,name,-1,SQLITE_TRANSIENT);sqlite3_bind_int(st,3,revision);
    if(!existing)sqlite3_bind_text(st,4,imported?"file_import":"manual",-1,SQLITE_STATIC);
    sqlite3_bind_int64(st,5,nc_now_s());
    if(sqlite3_step(st)!=SQLITE_DONE)goto rollback;
    sqlite3_finalize(st);st=NULL;
    if(directory&&!json_object_is_type(directory,json_type_null)) {
        if(sqlite3_prepare_v2(db,"INSERT INTO docker_compose_directory(project_id,revision,reference_json) VALUES(?1,?2,?3)",-1,&st,NULL)!=SQLITE_OK)goto rollback;
        sqlite3_bind_text(st,1,id,-1,SQLITE_TRANSIENT);sqlite3_bind_int(st,2,revision);
        sqlite3_bind_text(st,3,json_object_to_json_string_ext(directory,JSON_C_TO_STRING_PLAIN),-1,SQLITE_TRANSIENT);
        if(sqlite3_step(st)!=SQLITE_DONE)goto rollback;
        sqlite3_finalize(st);st=NULL;
    }
    if(sqlite3_exec(db,"COMMIT",NULL,NULL,NULL)!=SQLITE_OK)goto rollback;
    json_object_object_add(out,"ok",json_object_new_boolean(1));json_object_object_add(out,"persisted",json_object_new_boolean(1));
    json_object_object_add(out,"applied",json_object_new_boolean(0));json_object_object_add(out,"project",nc_docker_compose_meta(db,id));
    rc=0;goto done;
rollback:
    if(st){sqlite3_finalize(st);st=NULL;}
    sqlite3_exec(db,"ROLLBACK",NULL,NULL,NULL);
storage:
    if(!nc_docker_member(out,"error"))nc_docker_invalid(out,"compose_storage_failed");
done:
    if(st) { sqlite3_finalize(st); }if(meta) { json_object_put(meta); }
    ac_secrets_close(vault);if(db) { sqlite3_close(db); }
    if(imported){memset(imported,0,strlen(imported));free(imported);}return rc;
}

static struct json_object *nc_docker_registry_search(struct json_object *cfg)
{
    struct json_object *out=json_object_new_object();
    const char *keyword=nc_json_str_def(cfg,"keyword","");
    int page=nc_json_int_def(cfg,"page",1),size=nc_json_int_def(cfg,"page_size",20);
    if(!*keyword||strlen(keyword)>128||keyword[0]=='-'||page<1||size<1||size>25||page>100/size+1) {
        nc_docker_invalid(out,"invalid_search_query");return out;
    }
    const char *const argv[]={"docker","search","--limit","100","--no-trunc","--format","{{json .}}",keyword,NULL};
    struct json_object *rows=nc_docker_read_json(argv,1,NULL),*items=json_object_new_array();
    if(!rows){json_object_put(items);nc_docker_invalid(out,"search_unavailable");return out;}
    size_t count=json_object_array_length(rows),start=(size_t)(page-1)*size;
    for(size_t i=start;i<count&&i<start+(size_t)size;i++) {
        struct json_object *r=json_object_array_get_idx(rows,i),*item=json_object_new_object();
        nc_docker_copy(item,"name",r,"Name");nc_docker_copy(item,"description",r,"Description");
        nc_docker_copy(item,"stars",r,"StarCount");
        json_object_object_add(item,"official",json_object_new_boolean(!strcmp(nc_json_str_def(r,"IsOfficial",""),"[OK]")||!strcmp(nc_json_str_def(r,"IsOfficial",""),"true")));
        json_object_array_add(items,item);
    }
    json_object_put(rows);json_object_object_add(out,"ok",json_object_new_boolean(1));
    json_object_object_add(out,"items",items);json_object_object_add(out,"source",json_object_new_string("docker.io"));
    json_object_object_add(out,"page",json_object_new_int(page));json_object_object_add(out,"page_size",json_object_new_int(size));
    json_object_object_add(out,"matched_count",json_object_new_int64(count));
    json_object_object_add(out,"result_limit",json_object_new_int(100));
    json_object_object_add(out,"has_more",json_object_new_boolean(start+size<count));
    return out;
}

static struct json_object *nc_docker_compose_list(void)
{
    struct json_object *out=json_object_new_object(),*items=json_object_new_array();
    sqlite3 *db=NULL;sqlite3_stmt *st=NULL;
    if(nc_container_job_db_open(&db)||nc_docker_workflow_schema(db))goto failed;
    if(sqlite3_prepare_v2(db,"SELECT id FROM docker_compose_project WHERE deleted=0 ORDER BY updated_at DESC LIMIT 200",-1,&st,NULL)!=SQLITE_OK)goto failed;
    int step;
    while((step=sqlite3_step(st))==SQLITE_ROW) {
        const char *id=(const char *)sqlite3_column_text(st,0);
        struct json_object *meta=nc_docker_compose_meta(db,id);
        if(meta)json_object_array_add(items,meta);
    }
    if(step!=SQLITE_DONE)goto failed;
    sqlite3_finalize(st);st=NULL;sqlite3_close(db);db=NULL;
    /* All project membership is read from exact labels, never name prefixes. */
    const char *const argv[]={"docker","ps","-a","--no-trunc","--filter","label=com.docker.compose.project","--format","{{json .}}",NULL};
    struct json_object *containers=nc_docker_read_json(argv,1,NULL);
    if(containers) {
        for(size_t i=0;i<json_object_array_length(containers);i++) {
            struct json_object *row=json_object_array_get_idx(containers,i);
            char *labels=strdup(nc_json_str_def(row,"Labels","")),*save=NULL,*project=NULL;
            for(char *p=labels?strtok_r(labels,",",&save):NULL;p;p=strtok_r(NULL,",",&save))
                if(!strncmp(p,"com.docker.compose.project=",27))project=p+27;
            if(project&&*project) {
                struct json_object *item=NULL;
                for(size_t n=0;n<json_object_array_length(items);n++) {
                    struct json_object *candidate=json_object_array_get_idx(items,n);
                    if(!strcmp(project,nc_json_str_def(candidate,"engine_project","")))item=candidate;
                }
                if(!item) {
                    item=json_object_new_object();json_object_object_add(item,"id",json_object_new_string(project));
                    json_object_object_add(item,"name",json_object_new_string(project));json_object_object_add(item,"engine_project",json_object_new_string(project));
                    json_object_object_add(item,"source",json_object_new_string("external"));json_object_object_add(item,"managed",json_object_new_boolean(0));json_object_array_add(items,item);
                }
                struct json_object *services=nc_docker_member(item,"services");
                if(!services){services=json_object_new_array();json_object_object_add(item,"services",services);}
                struct json_object *service=json_object_new_object();nc_docker_copy(service,"id",row,"ID");nc_docker_copy(service,"name",row,"Names");nc_docker_copy(service,"state",row,"State");nc_docker_copy(service,"status",row,"Status");json_object_array_add(services,service);
            }
            free(labels);
        }
        json_object_put(containers);
    } else json_object_object_add(out,"runtime_error",json_object_new_string("docker_read_failed"));
    json_object_object_add(out,"ok",json_object_new_boolean(1));json_object_object_add(out,"projects",items);return out;
failed:
    if(st) { sqlite3_finalize(st); }if(db) { sqlite3_close(db); }json_object_put(items);nc_docker_invalid(out,"compose_storage_failed");return out;
}

static int nc_docker_compose_exec(sqlite3 *db,const char *id,int revision,const char *action,
                                  const char *service,struct nc_exec_result *result,int worker)
{
    char *yaml=nc_docker_compose_yaml(db,id,revision);struct nc_docker_compose_file f={0};
    if(!yaml)return 125;
    struct json_object *meta=nc_docker_compose_meta(db,id),*validation=json_object_new_object();
    struct json_object *model=nc_docker_compose_model(yaml,nc_docker_member(meta,"directory_ref"),id,validation);
    json_object_put(validation);if(meta)json_object_put(meta);
    memset(yaml,0,strlen(yaml));free(yaml);
    if(!model)return 125;
    int rc=nc_docker_compose_file_open(json_object_to_json_string_ext(model,JSON_C_TO_STRING_PLAIN|JSON_C_TO_STRING_NOSLASHESCAPE),&f);
    json_object_put(model);
    if(rc)return 125;
    const char *argv[24]={"docker","compose","--env-file","/dev/null","--ansi","never","-p",id,"-f",f.path};
    int n=10;
    if(!strcmp(action,"up")||!strcmp(action,"recreate")) {
        argv[n++]="up";argv[n++]="-d";argv[n++]="--no-build";
        if(!strcmp(action,"recreate"))argv[n++]="--force-recreate";
    } else if(!strcmp(action,"delete"))argv[n++]="down";
    else if(!strcmp(action,"logs")){argv[n++]="logs";argv[n++]="--no-color";argv[n++]="--tail";argv[n++]="200";}
    else argv[n++]=action;
    if(service&&*service)argv[n++]=service;
    argv[n]=NULL;
    rc=nc_exec_argv_capture_ex(argv,worker?1800:12,NC_CONTAINER_OUTPUT_MAX,result,!worker);
    nc_docker_compose_file_close(&f);return rc;
}

static int nc_docker_compose_action(struct json_object *cfg,struct json_object *out)
{
    const char *id=nc_json_str_def(cfg,"id",""),*action=nc_json_str_def(cfg,"operation","");
    if(!nc_docker_compose_id(id))return nc_docker_invalid(out,"invalid_project_id");
    const char *allowed[]={"up","stop","restart","pull","build","recreate","delete",NULL};int found=0;
    for(int i=0;allowed[i];i++)if(!strcmp(action,allowed[i]))found=1;
    if(!found)return nc_docker_invalid(out,"invalid_compose_action");
    if(!strcmp(action,"build")&&!nc_docker_compose_build_available())return nc_docker_invalid(out,"compose_buildx_unavailable");
    sqlite3 *db=NULL;struct json_object *meta=NULL;int rc=-1;
    if(nc_container_job_db_open(&db)||nc_docker_workflow_schema(db)){nc_docker_invalid(out,"compose_storage_failed");goto done;}
    meta=nc_docker_compose_meta(db,id);
    if(!meta){nc_docker_invalid(out,"compose_project_not_found");goto done;}
    if(!nc_docker_integer(nc_docker_member(cfg,"revision"),nc_json_int_def(meta,"revision",0),nc_json_int_def(meta,"revision",0))){nc_docker_invalid(out,"revision_conflict");goto done;}
    if(nc_docker_compose_busy(db,id)){nc_docker_invalid(out,"compose_project_busy");goto done;}
    if(!strcmp(action,"build")&&!nc_docker_member(meta,"directory_ref")){nc_docker_invalid(out,"compose_project_directory_required");goto done;}
    rc=nc_container_job_submit("compose_action",id,json_object_to_json_string_ext(cfg,JSON_C_TO_STRING_PLAIN),out);
done:
    if(meta) { json_object_put(meta); }
    if(db) { sqlite3_close(db); }return rc;
}

struct json_object *jmx_docker_workbench_read(struct json_object *cfg)
{
    const char *op=nc_json_str_def(cfg,"operation","");struct json_object *out=NULL;
    if(!strcmp(op,"network_edit"))out=nc_docker_network_edit_read(cfg);
    else if(!strcmp(op,"storage_preview"))out=nc_docker_migration_plan(cfg);
    else if(!strcmp(op,"network_options"))out=nc_docker_network_options();
    else if(!strcmp(op,"network_validate"))out=nc_docker_network_plan(cfg);
    else if(!strcmp(op,"cleanup_preview"))out=nc_docker_cleanup_preview();
    else if(!strcmp(op,"registry_search"))out=nc_docker_registry_search(cfg);
    else if(!strcmp(op,"container_template"))out=nc_docker_container_template(nc_json_str_def(cfg,"id",""));
    else if(!strcmp(op,"compose_list"))out=nc_docker_compose_list();
    else {
        out=json_object_new_object();sqlite3 *db=NULL;struct json_object *meta=NULL;
        const char *id=nc_json_str_def(cfg,"id","");
        if(!nc_docker_compose_id(id))nc_docker_invalid(out,"invalid_project_id");
        else if(nc_container_job_db_open(&db)||nc_docker_workflow_schema(db))nc_docker_invalid(out,"compose_storage_failed");
        else if(!(meta=nc_docker_compose_meta(db,id)))nc_docker_invalid(out,"compose_project_not_found");
        else if(!strcmp(op,"compose_config")) {
            char *yaml=nc_docker_compose_yaml(db,id,nc_json_int_def(meta,"revision",0));
            if(yaml){json_object_object_add(out,"ok",json_object_new_boolean(1));json_object_object_add(out,"yaml",json_object_new_string(yaml));memset(yaml,0,strlen(yaml));free(yaml);json_object_object_add(out,"project",json_object_get(meta));}
            else nc_docker_invalid(out,"compose_config_unavailable");
        } else if(!strcmp(op,"compose_logs")) {
            const char *service=nc_json_str_def(cfg,"service","");struct nc_exec_result r={0};
            if(*service&&!nc_docker_name_valid(service))nc_docker_invalid(out,"invalid_service_name");
            else {
                int rc=nc_docker_compose_exec(db,id,nc_json_int_def(meta,"revision",0),"logs",service,&r,0);
                json_object_object_add(out,"ok",json_object_new_boolean(!rc));json_object_object_add(out,"logs",json_object_new_string(r.output?r.output:""));json_object_object_add(out,"output_truncated",json_object_new_boolean(r.truncated));
                if(rc) { nc_docker_invalid(out,"compose_logs_unavailable"); }
                nc_exec_result_free(&r);
            }
        } else nc_docker_invalid(out,"invalid_workbench_operation");
        if(meta) { json_object_put(meta); }
        if(db) { sqlite3_close(db); }
    }
    return jmx_gen_api_response_data(nc_json_bool_def(out,"ok",0)?API_CODE_SUCCESS:API_CODE_ERROR,out);
}

int jmx_docker_workbench_write(struct json_object *cfg,struct json_object *out)
{
    if(nc_docker_confirmation_required(cfg,out))return -1;
    const char *op=nc_json_str_def(cfg,"operation","");
    if(!strcmp(op,"storage_migrate")||!strcmp(op,"storage_recover"))return nc_docker_migration_submit(cfg,out);
    if(!strcmp(op,"network_recreate"))return nc_docker_network_rebuild_submit(cfg,out);
    if(!strcmp(op,"config_apply")||!strcmp(op,"config_recover"))return nc_docker_settings_submit(cfg,out);
    if(!strcmp(op,"cleanup_execute")){if(nc_docker_cleanup_validate(cfg,out))return -1;return nc_container_job_submit("docker_cleanup","selected_objects",json_object_to_json_string_ext(cfg,JSON_C_TO_STRING_PLAIN),out);}
    if(!strcmp(op,"container_clone")||!strcmp(op,"container_recreate"))return nc_docker_replace_submit(cfg,out,!strcmp(op,"container_clone"));
    if(!strcmp(op,"container_recover"))return nc_docker_recover_submit(nc_json_str_def(cfg,"id",""),out);
    if(!strcmp(op,"compose_save"))return nc_docker_compose_save(cfg,out);
    if(!strcmp(op,"compose_validate")) {
        int rc=nc_docker_compose_validate(nc_json_str_def(cfg,"yaml",""),nc_docker_member(cfg,"directory_ref"),out);
        json_object_object_add(out,"ok",json_object_new_boolean(!rc));return rc;
    }
    if(!strcmp(op,"image_load")) {
        struct storage_files_stream file={.fd=-1};
        if(nc_docker_image_archive(cfg,&file,out))return -1;
        close(file.fd);
        return nc_container_job_submit("image_load",file.basename,json_object_to_json_string_ext(cfg,JSON_C_TO_STRING_PLAIN),out);
    }
    return nc_docker_compose_action(cfg,out);
}

static int nc_docker_workflow_execute(sqlite3 *db,const char *job,const char *kind,const char *target,
                                      struct json_object *cfg,struct nc_exec_result *result,
                                      struct json_object *detail)
{
    if(!strcmp(kind,"docker_migration"))return nc_docker_migration_execute(db,job,cfg,detail);
    if(!strcmp(kind,"network_recreate")||!strcmp(kind,"network_recover"))return nc_docker_network_rebuild_execute(db,job,cfg,detail,!strcmp(kind,"network_recover"));
    if(!strcmp(kind,"docker_config"))return nc_docker_settings_execute(job,cfg,detail);
    if(!strcmp(kind,"docker_cleanup"))return nc_docker_cleanup_execute(cfg,detail);
    if(!strcmp(kind,"container_clone")||!strcmp(kind,"container_recreate"))return nc_docker_replace_execute(db,job,cfg,detail,!strcmp(kind,"container_clone"));
    if(!strcmp(kind,"container_recover"))return nc_docker_recover_execute(db,job,cfg,detail);
    if(!strcmp(kind,"image_load")) {
        struct storage_files_stream file={.fd=-1};
        if(nc_docker_image_archive(cfg,&file,detail))return 125;
        char fdpath[64];snprintf(fdpath,sizeof(fdpath),"/proc/self/fd/%d",file.fd);
        if(fcntl(file.fd,F_SETFD,0)<0){close(file.fd);return 125;}
        const char *const argv[]={"docker","image","load","--input",fdpath,NULL};
        int rc=nc_exec_argv_capture_ex(argv,1800,NC_CONTAINER_OUTPUT_MAX,result,0);close(file.fd);
        struct json_object *loaded=json_object_new_array();char *text=result->output?strdup(result->output):NULL,*save=NULL;
        for(char *p=text?strtok_r(text,"\n",&save):NULL;p;p=strtok_r(NULL,"\n",&save)) {
            if(!strncmp(p,"Loaded image: ",14))json_object_array_add(loaded,json_object_new_string(p+14));
            else if(!strncmp(p,"Loaded image ID: ",17))json_object_array_add(loaded,json_object_new_string(p+17));
        }
        free(text);json_object_object_add(detail,"images",loaded);
        if(rc) { nc_docker_invalid(detail,"docker_image_load_failed"); }
        return rc;
    }
    if(!strcmp(kind,"compose_action")) {
        const char *action=nc_json_str_def(cfg,"operation","");int revision=nc_json_int_def(cfg,"revision",0);
        const char *allowed[]={"up","stop","restart","pull","build","recreate","delete",NULL};int valid=0;
        for(int i=0;allowed[i];i++)if(!strcmp(action,allowed[i]))valid=1;
        struct json_object *meta=nc_docker_compose_id(target)?nc_docker_compose_meta(db,target):NULL;
        if(!valid||!meta||nc_json_int_def(meta,"revision",0)!=revision) {
            if(meta) { json_object_put(meta); }
            nc_docker_invalid(detail,"revision_conflict");return 125;
        }
        json_object_put(meta);
        if(!strcmp(action,"build")&&!nc_docker_compose_build_available()){nc_docker_invalid(detail,"compose_buildx_unavailable");return 125;}
        int rc=nc_docker_compose_exec(db,target,revision,action,NULL,result,1);
        /* CLI errors can echo config values. Public jobs expose only the phase
         * and code; live application logs use the separately authorized route. */
        nc_exec_result_free(result);result->output=strdup(rc?"compose_operation_failed":"compose_operation_finished");
        json_object_object_add(detail,"project_id",json_object_new_string(target));
        json_object_object_add(detail,"revision",json_object_new_int(revision));
        json_object_object_add(detail,"operation",json_object_new_string(action));
        json_object_object_add(detail,"data_preserved",json_object_new_boolean(1));
        if(!rc&&!strcmp(action,"delete")) {
            sqlite3_stmt *st=NULL;
            if(sqlite3_prepare_v2(db,"UPDATE docker_compose_project SET deleted=1,updated_at=?2 WHERE id=?1",-1,&st,NULL)!=SQLITE_OK)rc=125;
            else {sqlite3_bind_text(st,1,target,-1,SQLITE_TRANSIENT);sqlite3_bind_int64(st,2,nc_now_s());if(sqlite3_step(st)!=SQLITE_DONE)rc=125;}
            if(st) { sqlite3_finalize(st); }
        }
        if(rc) { nc_docker_invalid(detail,"compose_operation_failed"); }
        return rc;
    }
    nc_docker_invalid(detail,"invalid_persisted_request");return 125;
}
