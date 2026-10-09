/* Offline Docker data-root migration. The existing settings row is the
 * journal/authority; container_job is the only executor. Never delete source. */
#include <dirent.h>
#include <sys/statvfs.h>
#include "storage/storage_provider.h"
#ifndef NC_DOCKER_MIGRATION_LOCK
#define NC_DOCKER_MIGRATION_LOCK "/var/run/dwrt-docker-migration.lock"
#endif
#ifndef NC_DOCKER_MIGRATION_PROC
#define NC_DOCKER_MIGRATION_PROC "/proc"
#endif
static int g_nc_docker_migration_owner;

/* An interrupted migration remains closed to writes until explicit recovery. */
static int nc_docker_migration_pending(void)
{
    sqlite3 *db=NULL;sqlite3_stmt *st=NULL;int pending=0;
    if(sqlite3_open_v2(NC_DOCKER_SETTINGS_DB,&db,SQLITE_OPEN_READONLY,NULL)==SQLITE_OK &&
       sqlite3_prepare_v2(db,"SELECT state FROM docker_engine_settings WHERE id=1",-1,&st,NULL)==SQLITE_OK &&
       sqlite3_step(st)==SQLITE_ROW) {
        const char *state=(const char *)sqlite3_column_text(st,0);
        pending=state&&!strncmp(state,"migration_",10);
    }
    if(st){sqlite3_finalize(st);}
    if(db){sqlite3_close(db);}
    return pending;
}

/* -2 means this process owns the exclusive lock. Other callers hold a shared
 * lock for the complete Engine call, including short synchronous mutations. */
static int nc_docker_migration_guard(void)
{
    if(g_nc_docker_migration_owner)return -2;
    int fd=open(NC_DOCKER_MIGRATION_LOCK,O_RDWR|O_CREAT|O_CLOEXEC,0600);
    if(fd<0)return -1;
    if(flock(fd,LOCK_SH|LOCK_NB)||nc_docker_migration_pending()){close(fd);return -1;}
    return fd;
}

static int nc_docker_migration_beneath(const char *path,const char *base)
{
    size_t n=strlen(base);
    return n>1&&!strncmp(path,base,n)&&(path[n]=='/'||!path[n]);
}

static int nc_docker_migration_empty(int fd)
{
    DIR *dir=fdopendir(dup(fd));struct dirent *entry;int empty=1;
    if(!dir)return 0;
    rewinddir(dir);
    while((entry=readdir(dir)))if(strcmp(entry->d_name,".")&&strcmp(entry->d_name,"..")){empty=0;break;}
    closedir(dir);return empty;
}

/* Read the same provider discovery used by storage management, then require a
 * stable, enabled fstab UUID binding for this exact mounted filesystem. */
static struct json_object *nc_docker_migration_mount(const char *path)
{
    struct jmx_storage_provider *items=calloc(JMX_STORAGE_PROVIDER_MAX,sizeof(*items));
    struct json_object *out=NULL;struct uci_context *ctx=uci_alloc_context();struct uci_package *pkg=NULL;
    if(!items||!ctx)goto done;
    uci_set_confdir(ctx,NC_DOCKER_UCI_DIR);
    if(uci_load(ctx,"fstab",&pkg)!=UCI_OK)goto done;
    int count=jmx_storage_provider_discover(items,JMX_STORAGE_PROVIDER_MAX),best=-1;
    for(int i=0;i<count;i++)if(items[i].mounted&&nc_docker_migration_beneath(path,items[i].mountpoint)&&
       (best<0||strlen(items[i].mountpoint)>strlen(items[best].mountpoint)))best=i;
    if(best<0)goto done;
    struct jmx_storage_provider *p=&items[best];struct stat actual,mounted;
    if(!p->uuid[0]||!p->writable||p->duplicate_mounts||
       (strcmp(p->filesystem,"ext4")&&strcmp(p->filesystem,"xfs")&&strcmp(p->filesystem,"btrfs")&&strcmp(p->filesystem,"f2fs"))||
       stat(path,&actual)||stat(p->mountpoint,&mounted)||actual.st_dev!=mounted.st_dev)goto done;
    int matches=0;struct uci_element *entry;
    uci_foreach_element(&pkg->sections,entry){
        struct uci_section *section=uci_to_section(entry);
        const char *uuid=uci_lookup_option_string(ctx,section,"uuid"),*enabled=uci_lookup_option_string(ctx,section,"enabled"),*target=uci_lookup_option_string(ctx,section,"target");
        if(!strcmp(section->type,"mount")&&uuid&&!strcmp(uuid,p->uuid)&&enabled&&!strcmp(enabled,"1")&&target&&!strcmp(target,p->mountpoint))matches++;
    }
    if(matches!=1)goto done;
    out=json_object_new_object();
    json_object_object_add(out,"uuid",json_object_new_string(p->uuid));
    json_object_object_add(out,"mountpoint",json_object_new_string(p->mountpoint));
    json_object_object_add(out,"filesystem",json_object_new_string(p->filesystem));
    json_object_object_add(out,"device",json_object_new_int64((int64_t)actual.st_dev));
done:
    free(items);if(ctx)uci_free_context(ctx);return out;
}

/* No symlink traversal. While online, skip runtime mounts; after stop, reject
 * them so --one-file-system cannot silently omit persistent data. Counts in a
 * preview are estimates (hard-linked file names can contribute more than once). */
static int nc_docker_migration_size(int fd,dev_t device,int offline,int depth,int64_t *bytes,int64_t *files)
{
    if(depth>128||*files>1000000)return -1;
    DIR *dir=fdopendir(dup(fd));struct dirent *entry;int rc=0;
    if(!dir)return -1;
    rewinddir(dir);
    while((entry=readdir(dir))){
        if(!strcmp(entry->d_name,".")||!strcmp(entry->d_name,".."))continue;
        struct stat st;
        if(fstatat(fd,entry->d_name,&st,AT_SYMLINK_NOFOLLOW)){rc=-1;break;}
        (*files)++;
        if(st.st_dev!=device){if(offline){rc=-1;break;}continue;}
        int64_t allocated=(int64_t)st.st_blocks*512;
        *bytes+=S_ISREG(st.st_mode)&&st.st_size>allocated?st.st_size:allocated;
        if(S_ISDIR(st.st_mode)){
            int child=openat(fd,entry->d_name,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
            if(child<0){rc=-1;break;}
            rc=nc_docker_migration_size(child,device,offline,depth+1,bytes,files);close(child);
            if(rc)break;
        }
    }
    closedir(dir);return rc;
}

/* Managed containerd must be positively associated with the socket reported
 * by this Engine. External/shared roots are deliberately not moved. */
static struct json_object *nc_docker_migration_containerd(struct json_object *info,const char *source)
{
    const char *address=nc_json_str_def(nc_docker_member(info,"Containerd"),"Address","");
    char socket[PATH_MAX];if(!realpath(address,socket))return NULL;
    DIR *proc=opendir(NC_DOCKER_MIGRATION_PROC);struct dirent *entry;struct json_object *out=NULL;
    if(!proc)return NULL;
    while((entry=readdir(proc))){
        if(!isdigit((unsigned char)entry->d_name[0]))continue;
        char path[PATH_MAX],cmd[8192],config[PATH_MAX]="";
        snprintf(path,sizeof(path),NC_DOCKER_MIGRATION_PROC "/%s/cmdline",entry->d_name);
        FILE *fp=fopen(path,"r");if(!fp)continue;
        size_t n=fread(cmd,1,sizeof(cmd)-1,fp);fclose(fp);cmd[n]=0;
        const char *base=strrchr(cmd,'/');base=base?base+1:cmd;
        if(strcmp(base,"containerd"))continue;
        for(size_t i=strlen(cmd)+1;i<n;i+=strlen(cmd+i)+1){
            if(!strcmp(cmd+i,"--config")&&i+9<n)snprintf(config,sizeof(config),"%s",cmd+i+9);
            else if(!strncmp(cmd+i,"--config=",9))snprintf(config,sizeof(config),"%s",cmd+i+9);
        }
        if(!config[0]||!(fp=fopen(config,"r")))continue;
        char line[PATH_MAX+64],root[PATH_MAX]="",grpc[PATH_MAX]="";int section=0;
        while(fgets(line,sizeof(line),fp)){
            char key[32],value[PATH_MAX],opening,closing;int end=0;
            char *p=line;while(isspace((unsigned char)*p))p++;
            if(*p=='['){section=!strncmp(p,"[grpc]",6)?1:2;continue;}
            if(sscanf(p,"%31[a-z_] = %c%4095[^\"']%c%n",key,&opening,value,&closing,&end)==4 && end &&
               (opening=='\"'||opening=='\'')&&opening==closing){
                if(section==0&&!strcmp(key,"root"))snprintf(root,sizeof(root),"%s",value);
                if(section==1&&!strcmp(key,"address"))snprintf(grpc,sizeof(grpc),"%s",value);
            }
        }
        fclose(fp);char actual[PATH_MAX],resolved[PATH_MAX];
        if(!realpath(grpc,resolved)||strcmp(resolved,socket)||!realpath(root,actual))continue;
        if(!nc_docker_migration_beneath(actual,source)||!strcmp(actual,source)){
            if(out){json_object_put(out);}out=NULL;break;
        }
        if(out){json_object_put(out);out=NULL;break;}
        out=json_object_new_object();
        json_object_object_add(out,"root",json_object_new_string(actual));
        json_object_object_add(out,"relative_root",json_object_new_string(actual+strlen(source)));
        json_object_object_add(out,"pid",json_object_new_int(atoi(entry->d_name)));
        json_object_object_add(out,"config",json_object_new_string(config));
    }
    closedir(proc);return out;
}

/* This snapshot contains identities/state only, never env or secrets. */
static int nc_docker_migration_sort(const void *a,const void *b)
{
    return strcmp(nc_json_str_def(*(struct json_object *const *)a,"id",""),nc_json_str_def(*(struct json_object *const *)b,"id",""));
}

static struct json_object *nc_docker_migration_inventory(struct json_object *out,const char *source)
{
    long status=0;struct json_object *inventory=json_object_new_object();
    const char *paths[]={"/containers/json?all=1","/images/json?all=1","/volumes","/networks"};
    const char *keys[]={"containers","images","volumes","networks"};
    for(int k=0;k<4;k++){
        struct json_object *raw=nc_docker_engine_request("GET",paths[k],NULL,&status),*rows=k==2?nc_docker_member(raw,"Volumes"):raw;
        if(status!=200||!json_object_is_type(rows,json_type_array)){if(raw){json_object_put(raw);}goto fail;}
        struct json_object *list=json_object_new_array();json_object_object_add(inventory,keys[k],list);
        for(size_t i=0;i<json_object_array_length(rows);i++){
            struct json_object *item=json_object_array_get_idx(rows,i),*record=json_object_new_object();
            const char *id=nc_json_str_def(item,k==2?"Name":"Id","");
            if(!*id){json_object_put(record);json_object_put(raw);goto fail;}
            json_object_object_add(record,"id",json_object_new_string(id));
            if(k==0){
                struct json_object *inspect=nc_docker_raw_container(id),*state=nc_docker_member(inspect,"State"),*host=nc_docker_member(inspect,"HostConfig");
                if(!inspect||nc_json_bool_def(host,"AutoRemove",0)||nc_json_bool_def(state,"Paused",0)||nc_json_bool_def(state,"Restarting",0)){
                    if(inspect){json_object_put(inspect);}json_object_put(record);json_object_put(raw);goto fail;
                }
                struct json_object *mounts=nc_docker_member(inspect,"Mounts");
                for(size_t m=0;m<json_object_array_length(mounts);m++){
                    struct json_object *mount=json_object_array_get_idx(mounts,m);char path[PATH_MAX];
                    if(!strcmp(nc_json_str_def(mount,"Type",""),"bind")&&realpath(nc_json_str_def(mount,"Source",""),path)&&nc_docker_migration_beneath(path,source)){
                        nc_docker_invalid(out,"docker_migration_bind_inside_data_root");
                        json_object_object_add(out,"blocked_container",json_object_new_string(id));
                        json_object_put(inspect);json_object_put(record);json_object_put(raw);goto fail;
                    }
                }
                nc_docker_copy(record,"name",inspect,"Name");nc_docker_copy(record,"image",inspect,"Image");
                nc_docker_copy(record,"running",state,"Running");json_object_put(inspect);
            }else if(k==2 && (strcmp(nc_json_str_def(item,"Driver",""),"local")||(nc_docker_member(item,"Options") && (!json_object_is_type(nc_docker_member(item,"Options"),json_type_object)||json_object_object_length(nc_docker_member(item,"Options")))))){
                json_object_put(record);json_object_put(raw);goto fail;
            }
            json_object_array_add(list,record);
        }
        json_object_array_sort(list,nc_docker_migration_sort);
        json_object_put(raw);
    }
    return inventory;
fail:
    json_object_put(inventory);if(!nc_docker_member(out,"error"))nc_docker_invalid(out,"docker_migration_inventory_unsupported");return NULL;
}

/* A leftover bind/overlay mount must not turn the offline copy into a partial
 * tree, including a bind mount whose device number equals its parent. */
static int nc_docker_migration_has_submount(const char *source)
{
    FILE *fp=fopen("/proc/self/mountinfo","r");char line[8192],path[4096];int found=0;
    if(!fp)return 1;
    while(fgets(line,sizeof(line),fp)){
        if(sscanf(line,"%*s %*s %*s %*s %4095s",path)!=1){found=1;break;}
        char *read=path,*write=path;
        while(*read){
            if(read[0]=='\\'&&read[1]>='0'&&read[1]<='7'&&read[2]>='0'&&read[2]<='7'&&read[3]>='0'&&read[3]<='7'){
                *write++=(char)((read[1]-'0')*64+(read[2]-'0')*8+read[3]-'0');read+=4;
            }else *write++=*read++;
        }
        *write=0;
        if(strcmp(path,source)&&nc_docker_migration_beneath(path,source)){found=1;break;}
    }
    fclose(fp);return found;
}

static int nc_docker_migration_revision(struct json_object *plan,char hex[65])
{
    unsigned char digest[32];unsigned int n=0;
    const char *text=json_object_to_json_string_ext(plan,JSON_C_TO_STRING_PLAIN);
    if(!EVP_Digest(text,strlen(text),digest,&n,EVP_sha256(),NULL)||n!=32)return -1;
    for(unsigned i=0;i<n;i++){snprintf(hex+i*2,3,"%02x",digest[i]);}
    return 0;
}

static struct json_object *nc_docker_migration_plan(struct json_object *cfg)
{
    struct json_object *out=json_object_new_object(),*live=NULL,*row=NULL,*info=NULL,*mount=NULL,*containerd=NULL,*inventory=NULL;
    sqlite3 *db=NULL;int source_fd=-1,target_fd=-1;char source[PATH_MAX],target[PATH_MAX],configured[PATH_MAX],revision[65];
    const char *reason=NULL;struct stat src,dst;struct statvfs space;
    const char *const argv[]={"docker","info","--format","{{json .}}",NULL};
    struct json_object *ref=nc_docker_member(cfg,"directory_ref");
    if(!nc_cmd_exists("rsync")){reason="rsync_unavailable";goto fail;}
    const char *const rsync_version[]={"rsync","--version",NULL};struct nc_exec_result version={0};
    int supported=nc_exec_argv_capture(rsync_version,5,8192,&version)==0 && version.output &&
        !strstr(version.output,"no ACLs")&&!strstr(version.output,"no xattrs")&&!strstr(version.output,"no hardlinks");
    nc_exec_result_free(&version);
    if(!supported){reason="rsync_metadata_support_unavailable";goto fail;}
    if(nc_docker_settings_db(&db)||(row=nc_docker_settings_row(db))==NULL){reason="docker_settings_storage_failed";goto fail;}
    if(strcmp(nc_json_str_def(row,"state",""),"idle")){reason="docker_settings_recovery_or_apply_pending";goto fail;}
    if(!json_object_equal(nc_docker_member(row,"config"),nc_docker_member(row,"applied_config"))){reason="docker_settings_apply_pending";goto fail;}
    live=nc_docker_settings_live();info=nc_docker_read_json(argv,0,NULL);
    if(!nc_json_bool_def(live,"ok",0)||strcmp(nc_json_str_def(live,"fingerprint",""),nc_json_str_def(row,"uci_fingerprint",""))){reason="docker_settings_external_change";goto fail;}
    if(!info||nc_docker_settings_service("running")!=0){reason="docker_engine_not_running";goto fail;}
    const char *driver=nc_json_str_def(info,"Driver","");
    if(strcmp(driver,"overlayfs")&&strcmp(driver,"overlay2")&&strcmp(driver,"vfs")){reason="docker_migration_driver_unsupported";goto fail;}
    if(nc_json_bool_def(info,"LiveRestoreEnabled",0)||strcmp(nc_json_str_def(nc_docker_member(info,"Swarm"),"LocalNodeState","inactive"),"inactive")){reason="docker_migration_live_restore_or_swarm";goto fail;}
    if(!realpath(nc_json_str_def(info,"DockerRootDir",""),source)||strlen(source)<5||
       !realpath(nc_json_str_def(live,"data_root",""),configured)||strcmp(source,configured)){reason="docker_data_root_unresolved";goto fail;}
    containerd=nc_docker_migration_containerd(info,source);
    if(!containerd){reason="docker_containerd_root_unresolved_or_external";goto fail;}
    const char *const keys[]={"root_id","path",NULL};
    if(!nc_docker_keys(ref,keys)||!nc_docker_string(nc_docker_member(ref,"root_id"),47)||!nc_docker_string(nc_docker_member(ref,"path"),PATH_MAX-1)){reason="invalid_directory_reference";goto fail;}
    target_fd=storage_files_open_dir(nc_json_str_def(ref,"root_id",""),nc_json_str_def(ref,"path",""),1,target,sizeof(target),&reason);
    if(target_fd<0)goto fail;
    if(nc_docker_migration_beneath(target,source)||nc_docker_migration_beneath(source,target)){reason="docker_migration_paths_overlap";goto fail;}
    if(!nc_docker_migration_empty(target_fd)){reason="docker_migration_target_not_empty";goto fail;}
    if(!(mount=nc_docker_migration_mount(target))){reason="docker_migration_target_not_persistent";goto fail;}
    source_fd=open(source,O_RDONLY|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW);
    if(source_fd<0||fstat(source_fd,&src)||fstat(target_fd,&dst)||statvfs(target,&space)){reason="docker_migration_path_unavailable";goto fail;}
    inventory=nc_docker_migration_inventory(out,source);if(!inventory)goto done;
    json_object_object_add(out,"source",json_object_new_string(source));
    json_object_object_add(out,"target",json_object_new_string(target));
    json_object_object_add(out,"source_device",json_object_new_int64((int64_t)src.st_dev));
    json_object_object_add(out,"source_inode",json_object_new_int64((int64_t)src.st_ino));
    json_object_object_add(out,"target_inode",json_object_new_int64((int64_t)dst.st_ino));
    json_object_object_add(out,"mount",json_object_get(mount));
    json_object_object_add(out,"containerd",json_object_get(containerd));
    json_object_object_add(out,"inventory",json_object_get(inventory));
    nc_docker_copy(out,"settings_revision",row,"revision");nc_docker_copy(out,"settings_fingerprint",row,"uci_fingerprint");
    nc_docker_copy(out,"engine_id",info,"ID");
    if(nc_docker_migration_revision(out,revision)){reason="docker_migration_revision_failed";goto fail;}
    int64_t bytes=0,files=0;
    if(nc_docker_migration_size(source_fd,src.st_dev,0,0,&bytes,&files)){reason="docker_migration_size_unavailable";goto fail;}
    uint64_t available=(uint64_t)space.f_bavail*space.f_frsize,required=(uint64_t)bytes+(uint64_t)bytes/10+67108864;
    json_object_object_add(out,"estimated_bytes",json_object_new_int64(bytes));
    json_object_object_add(out,"estimated_files",json_object_new_int64(files));
    json_object_object_add(out,"available_bytes",json_object_new_int64((int64_t)available));
    json_object_object_add(out,"required_bytes",json_object_new_int64((int64_t)required));
    if(available<required||(space.f_files&&space.f_favail<(uint64_t)files)){reason="docker_migration_insufficient_space";goto fail;}
    json_object_object_add(out,"can_migrate",json_object_new_boolean(1));
    json_object_object_add(out,"revision",json_object_new_string(revision));
    json_object_object_add(out,"ok",json_object_new_boolean(1));goto done;
fail:
    nc_docker_invalid(out,reason?reason:"docker_migration_preflight_failed");
done:
    if(source_fd>=0){close(source_fd);}if(target_fd>=0){close(target_fd);}
    if(db){sqlite3_close(db);}if(row){json_object_put(row);}if(live){json_object_put(live);}if(info){json_object_put(info);}
    if(mount){json_object_put(mount);}if(containerd){json_object_put(containerd);}if(inventory){json_object_put(inventory);}
    return out;
}

static int nc_docker_migration_record(sqlite3 *settings,sqlite3 *jobs,const char *job,const char *phase,
                                     struct json_object *journal,struct json_object *out)
{
    char state[64];snprintf(state,sizeof(state),"migration_%s",phase);
    json_object_object_add(out,"phase",json_object_new_string(phase));
    json_object_object_add(out,"source_retained",json_object_new_boolean(1));
    if(nc_docker_settings_record(settings,state,journal,out,NULL))return -1;
    sqlite3_stmt *st=NULL;int rc=-1;
    if(sqlite3_prepare_v2(jobs,"UPDATE container_job SET result_json=?1,updated_at=?2 WHERE id=?3 AND state='running'",-1,&st,NULL)==SQLITE_OK){
        sqlite3_bind_text(st,1,json_object_to_json_string_ext(out,JSON_C_TO_STRING_PLAIN),-1,SQLITE_TRANSIENT);
        sqlite3_bind_int64(st,2,nc_now_s());sqlite3_bind_text(st,3,job,-1,SQLITE_TRANSIENT);
        if(sqlite3_step(st)==SQLITE_DONE)rc=0;
    }
    if(st){sqlite3_finalize(st);}return rc;
}

static int nc_docker_migration_publish_root(const char *root,sqlite3 *db,sqlite3 *jobs,const char *job,struct json_object *journal,struct json_object *out)
{
    struct uci_package *pkg=NULL;struct uci_context *ctx=nc_docker_settings_uci(&pkg);int rc=-1;FILE *fp=NULL;
    const char *temp=NC_DOCKER_UCI_DIR "/.dockerd.dwrt-migration";
    if(!ctx)return -1;
    struct uci_section *s=uci_lookup_section(ctx,pkg,"globals");
    struct uci_ptr ptr={.p=pkg,.s=s,.section="globals",.option="data_root",.value=root};
    if(!s||uci_set(ctx,&ptr))goto done;
    int fd=open(temp,O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600);
    if(fd<0)goto done;
    fp=fdopen(fd,"w");if(!fp){close(fd);goto done;}
    if(uci_export(ctx,fp,pkg,false)||fflush(fp)||fsync(fileno(fp)))goto done;
    if(fclose(fp)){fp=NULL;goto done;}fp=NULL;
    unsigned char bytes[65537],digest[32];unsigned int count=0;char fingerprint[65];
    fp=fopen(temp,"rb");if(!fp)goto done;
    size_t length=fread(bytes,1,sizeof(bytes)-1,fp);fclose(fp);fp=NULL;
    if(length>=sizeof(bytes)-1)goto done;
    int enabled=nc_docker_settings_service("enabled");if(enabled!=0&&enabled!=1)goto done;
    bytes[length++]=enabled==0;
    if(!EVP_Digest(bytes,length,digest,&count,EVP_sha256(),NULL)||count!=32)goto done;
    for(unsigned i=0;i<count;i++)snprintf(fingerprint+i*2,3,"%02x",digest[i]);
    json_object_object_add(journal,"switch_fingerprint",json_object_new_string(fingerprint));
    if(nc_docker_migration_record(db,jobs,job,"switching",journal,out))goto done;
    if(rename(temp,NC_DOCKER_UCI_DIR "/dockerd"))goto done;
    int parent=open(NC_DOCKER_UCI_DIR,O_RDONLY|O_DIRECTORY|O_CLOEXEC);
    rc=parent>=0?fsync(parent):-1;if(parent>=0){close(parent);}
done:
    if(fp){fclose(fp);}if(rc){unlink(temp);}uci_free_context(ctx);return rc;
}

static int nc_docker_migration_container_states(struct json_object *inventory,int start,struct json_object *out)
{
    struct json_object *containers=nc_docker_member(inventory,"containers");
    for(size_t i=0;i<json_object_array_length(containers);i++){
        struct json_object *row=json_object_array_get_idx(containers,i);
        int expected=nc_json_bool_def(row,"running",0);
        if(!start&&!expected)continue;
        char path[256];long status=0;const char *id=nc_json_str_def(row,"id","");
        if(start&&!expected){
            struct json_object *raw=nc_docker_raw_container(id);
            if(!raw)return -1;
            int running=nc_json_bool_def(nc_docker_member(raw,"State"),"Running",0);
            json_object_put(raw);if(!running)continue;
        }
        snprintf(path,sizeof(path),"/containers/%s/%s",id,start&&expected?"start":"stop?t=30");
        struct json_object *r=nc_docker_engine_request("POST",path,NULL,&status);if(r){json_object_put(r);}
        if(status!=204&&status!=304){json_object_object_add(out,"blocked_container",json_object_new_string(id));return -1;}
    }
    return 0;
}

static int nc_docker_migration_readback(struct json_object *journal,const char *root,struct json_object *out)
{
    const char *const argv[]={"docker","info","--format","{{json .}}",NULL};
    struct json_object *info=NULL;char actual[PATH_MAX];int ready=0;
    for(int i=0;i<40;i++){
        info=nc_docker_read_json(argv,0,NULL);
        ready=info&&realpath(nc_json_str_def(info,"DockerRootDir",""),actual)&&!strcmp(actual,root);
        if(ready)break;
        if(info){json_object_put(info);}info=NULL;usleep(250000);
    }
    if(!ready)return -1;
    struct json_object *cd=nc_docker_migration_containerd(info,root);
    ready=cd&&!strcmp(nc_json_str_def(cd,"relative_root",""),nc_json_str_def(nc_docker_member(journal,"containerd"),"relative_root",""));
    if(cd){json_object_put(cd);}json_object_put(info);if(!ready)return -1;
    struct json_object *inventory=nc_docker_member(journal,"inventory");
    if(nc_docker_migration_container_states(inventory,1,out))return -1;
    struct json_object *current=nc_docker_migration_inventory(out,root);if(!current)return -1;
    const char *keys[]={"containers","images","volumes","networks"};
    int ok=1;
    for(int k=0;k<4&&ok;k++){
        struct json_object *before=nc_docker_member(inventory,keys[k]),*after=nc_docker_member(current,keys[k]);
        if(json_object_array_length(before)!=json_object_array_length(after)){ok=0;break;}
        for(size_t a=0;a<json_object_array_length(before)&&ok;a++){
            struct json_object *item=json_object_array_get_idx(before,a);int found=0;
            for(size_t b=0;b<json_object_array_length(after);b++)if(json_object_equal(item,json_object_array_get_idx(after,b))){found=1;break;}
            if(!found)ok=0;
        }
    }
    json_object_put(current);return ok?0:-1;
}

static int nc_docker_migration_commit(sqlite3 *db,struct json_object *config,struct json_object *out)
{
    sqlite3_stmt *st=NULL;int rc=-1;
    if(sqlite3_exec(db,"BEGIN IMMEDIATE",NULL,NULL,NULL)!=SQLITE_OK)return -1;
    if(sqlite3_prepare_v2(db,"UPDATE docker_engine_settings SET desired=?1,revision=revision+1 WHERE id=1",-1,&st,NULL)!=SQLITE_OK)goto done;
    sqlite3_bind_text(st,1,json_object_to_json_string_ext(config,JSON_C_TO_STRING_PLAIN),-1,SQLITE_TRANSIENT);
    if(sqlite3_step(st)!=SQLITE_DONE||nc_docker_settings_record(db,"idle",NULL,out,config))goto done;
    if(sqlite3_exec(db,"COMMIT",NULL,NULL,NULL)==SQLITE_OK)rc=0;
done:
    if(st){sqlite3_finalize(st);}if(rc){sqlite3_exec(db,"ROLLBACK",NULL,NULL,NULL);}
    return rc;
}

static int nc_docker_migration_restore(sqlite3 *db,sqlite3 *jobs,const char *job,struct json_object *journal,struct json_object *out)
{
    const char *backup=nc_json_str_def(journal,"backup",""),*source=nc_json_str_def(journal,"source","");
    struct json_object *previous=nc_docker_member(journal,"previous");struct stat st;
    int rc=-1;
    if(!previous||strncmp(backup,NC_DOCKER_UCI_DIR "/.dockerd.dwrt-job-",strlen(NC_DOCKER_UCI_DIR "/.dockerd.dwrt-job-"))||
       stat(source,&st)||(int64_t)st.st_dev!=json_object_get_int64(nc_docker_member(journal,"source_device"))||
       (int64_t)st.st_ino!=json_object_get_int64(nc_docker_member(journal,"source_inode")))goto done;
    char fingerprint[65];
    if(nc_docker_settings_fingerprint(fingerprint)||
       (strcmp(fingerprint,nc_json_str_def(journal,"settings_fingerprint",""))&&strcmp(fingerprint,nc_json_str_def(journal,"switch_fingerprint","")))){
        nc_docker_invalid(out,"docker_settings_external_change");goto done;
    }
    if(nc_docker_migration_record(db,jobs,job,"restoring",journal,out))goto done;
    if(nc_docker_settings_service("stop"))goto done;
    const char *temp=NC_DOCKER_UCI_DIR "/.dockerd.dwrt-restore";
    if(nc_docker_settings_copy(backup,temp,0)||rename(temp,NC_DOCKER_UCI_DIR "/dockerd")||
       nc_docker_settings_service("start")||nc_docker_migration_readback(journal,source,out))goto done;
    json_object_object_add(out,"rollback",json_object_new_string("restored"));
    json_object_object_add(out,"phase",json_object_new_string("restored"));
    rc=nc_docker_migration_commit(db,previous,out);
done:
    if(rc){json_object_object_add(out,"rollback",json_object_new_string("failed"));nc_docker_migration_record(db,jobs,job,"recovery_required",journal,out);}
    return rc;
}

/* rsync is executed without a shell, with pinned directory descriptors. Dry-run
 * checksum verification can mention --delete but never removes anything. */
static int nc_docker_migration_copy(sqlite3 *db,sqlite3 *jobs,const char *job,struct json_object *journal,
                                    struct json_object *out,int source,int target,int verify)
{
    int pipes[2];if(pipe(pipes))return -1;
    pid_t pid=fork();if(pid<0){close(pipes[0]);close(pipes[1]);return -1;}
    if(!pid){
        close(pipes[0]);dup2(pipes[1],STDOUT_FILENO);dup2(pipes[1],STDERR_FILENO);close(pipes[1]);
        fcntl(source,F_SETFD,0);fcntl(target,F_SETFD,0);setenv("LC_ALL","C",1);
        char from[64],to[64];snprintf(from,sizeof(from),"/proc/self/fd/%d/",source);snprintf(to,sizeof(to),"/proc/self/fd/%d/",target);
        if(verify)execlp("rsync","rsync","-aHAXSnic","--numeric-ids","--one-file-system","--delete","--out-format=%i","--",from,to,(char *)NULL);
        else execlp("rsync","rsync","-aHAXS","--numeric-ids","--one-file-system","--fsync","--info=progress2","--no-inc-recursive","--outbuf=L","--",from,to,(char *)NULL);
        _exit(127);
    }
    close(pipes[1]);int flags=fcntl(pipes[0],F_GETFL);fcntl(pipes[0],F_SETFL,flags|O_NONBLOCK);
    int status=0,done=0,eof=0,difference=0;char line[2048];size_t used=0;int64_t last=0,deadline=nc_container_monotonic_ms()+21600000;
    while(!done||!eof){
        char buffer[2048];ssize_t n=read(pipes[0],buffer,sizeof(buffer));
        if(n==0)eof=1;
        if(n>0){
            if(verify)difference=1;
            for(ssize_t i=0;i<n;i++){
                if(buffer[i]=='\r'||buffer[i]=='\n'){
                    line[used]=0;char digits[64];size_t len=0;const char *p=line;while(*p==' ')p++;
                    while(isdigit((unsigned char)*p)||*p==','){if(*p!=','&&len<sizeof(digits)-1)digits[len++]=*p;p++;}digits[len]=0;
                    const char *x=strstr(line,"xfr#");
                    if(!verify&&len&&strchr(p,'%')){
                        json_object_object_add(out,"copied_bytes",json_object_new_int64(strtoll(digits,NULL,10)));
                        if(x)json_object_object_add(out,"copied_files",json_object_new_int64(strtoll(x+4,NULL,10)));
                        if(nc_container_monotonic_ms()-last>=500){nc_docker_migration_record(db,jobs,job,"copying",journal,out);last=nc_container_monotonic_ms();}
                    }
                    used=0;
                }else if(used<sizeof(line)-1)line[used++]=buffer[i];
            }
        }
        if(!done){
            pid_t waited=waitpid(pid,&status,WNOHANG);
            if(waited==pid)done=1;
            else if(waited<0&&errno!=EINTR){status=127<<8;done=1;}
        }
        if(!done&&nc_container_monotonic_ms()>deadline){kill(pid,SIGKILL);waitpid(pid,&status,0);done=1;status=124<<8;}
        if(!done||!eof){struct pollfd poller={.fd=pipes[0],.events=POLLIN|POLLHUP};poll(&poller,1,100);}
    }
    close(pipes[0]);int rc=WIFEXITED(status)?WEXITSTATUS(status):125;
    json_object_object_add(out,verify?"verify_rc":"copy_rc",json_object_new_int(rc));
    return rc||difference?-1:0;
}

static int nc_docker_migration_execute(sqlite3 *jobs,const char *job,struct json_object *cfg,struct json_object *out)
{
    int lock=-1,settings_lock=-1,source=-1,target=-1,rc=125;sqlite3 *db=NULL;
    struct json_object *plan=NULL,*row=NULL,*journal=NULL;struct stat src,dst;
    lock=open(NC_DOCKER_MIGRATION_LOCK,O_RDWR|O_CREAT|O_CLOEXEC,0600);
    if(lock<0||flock(lock,LOCK_EX|LOCK_NB)){nc_docker_invalid(out,"docker_migration_busy");goto done;}
    g_nc_docker_migration_owner=1;
    settings_lock=open(NC_DOCKER_SETTINGS_LOCK,O_RDWR|O_CREAT|O_CLOEXEC,0600);
    if(settings_lock<0||flock(settings_lock,LOCK_EX|LOCK_NB)){nc_docker_invalid(out,"docker_settings_busy");goto done;}
    if(nc_docker_settings_db(&db)||!(row=nc_docker_settings_row(db))){nc_docker_invalid(out,"docker_settings_storage_failed");goto done;}
    if(!strcmp(nc_json_str_def(cfg,"operation",""),"storage_recover")){
        if(strncmp(nc_json_str_def(row,"state",""),"migration_",10)){nc_docker_invalid(out,"docker_migration_no_recovery");goto done;}
        journal=json_object_get(nc_docker_member(row,"recovery"));
        nc_docker_copy(out,"source",journal,"source");nc_docker_copy(out,"target",journal,"target");nc_docker_copy(out,"backup",journal,"backup");
        rc=nc_docker_migration_restore(db,jobs,job,journal,out)?125:0;
        json_object_object_add(out,"ok",json_object_new_boolean(!rc));goto done;
    }
    plan=nc_docker_migration_plan(cfg);
    if(!nc_json_bool_def(plan,"ok",0)){nc_docker_invalid(out,nc_json_str_def(plan,"error","docker_migration_preflight_failed"));goto done;}
    if(strcmp(nc_json_str_def(cfg,"revision",""),nc_json_str_def(plan,"revision",""))){nc_docker_invalid(out,"revision_conflict");goto done;}
    const char *from=nc_json_str_def(plan,"source",""),*to=nc_json_str_def(plan,"target","");
    source=open(from,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);target=open(to,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
    if(source<0||target<0||fstat(source,&src)||fstat(target,&dst)||!nc_docker_migration_empty(target)){nc_docker_invalid(out,"docker_migration_path_changed");goto done;}
    if((int64_t)src.st_dev!=json_object_get_int64(nc_docker_member(plan,"source_device"))||
       (int64_t)src.st_ino!=json_object_get_int64(nc_docker_member(plan,"source_inode"))||
       (int64_t)dst.st_ino!=json_object_get_int64(nc_docker_member(plan,"target_inode"))||
       (int64_t)dst.st_dev!=json_object_get_int64(nc_docker_member(nc_docker_member(plan,"mount"),"device"))){nc_docker_invalid(out,"docker_migration_path_changed");goto done;}
    journal=json_object_get(plan);char backup[256];snprintf(backup,sizeof(backup),NC_DOCKER_UCI_DIR "/.dockerd.dwrt-%s.bak",job);
    if(nc_docker_settings_copy(NC_DOCKER_UCI_DIR "/dockerd",backup,1)){nc_docker_invalid(out,"docker_settings_backup_failed");goto done;}
    json_object_object_add(journal,"backup",json_object_new_string(backup));
    json_object_object_add(journal,"previous",json_object_get(nc_docker_member(row,"config")));
    nc_docker_copy(out,"source",plan,"source");nc_docker_copy(out,"target",plan,"target");
    json_object_object_add(out,"backup",json_object_new_string(backup));
    if(nc_docker_migration_record(db,jobs,job,"stopping",journal,out))goto done;
    if(nc_docker_migration_container_states(nc_docker_member(journal,"inventory"),0,out)||nc_docker_settings_service("stop"))goto restore;
    char proc[128];snprintf(proc,sizeof(proc),NC_DOCKER_MIGRATION_PROC "/%d/cmdline",nc_json_int_def(nc_docker_member(journal,"containerd"),"pid",0));
    for(int i=0;i<100&&access(proc,F_OK)==0;i++)usleep(100000);
    long status=0;struct json_object *ping=nc_docker_engine_request("GET","/_ping",NULL,&status);if(ping){json_object_put(ping);}
    if(status==200||nc_docker_settings_service("running")!=1||access(proc,F_OK)==0){nc_docker_invalid(out,"docker_migration_engine_not_stopped");goto restore;}
    int64_t bytes=0,files=0;struct statvfs space;
    if(nc_docker_migration_has_submount(from)||nc_docker_migration_size(source,src.st_dev,1,0,&bytes,&files)||fstatvfs(target,&space)||
       (uint64_t)space.f_bavail*space.f_frsize<(uint64_t)bytes+(uint64_t)bytes/10+67108864){nc_docker_invalid(out,"docker_migration_offline_space_or_mount_changed");goto restore;}
    json_object_object_add(out,"total_bytes",json_object_new_int64(bytes));json_object_object_add(out,"total_files",json_object_new_int64(files));
    if(nc_docker_migration_record(db,jobs,job,"copying",journal,out)||nc_docker_migration_copy(db,jobs,job,journal,out,source,target,0)){nc_docker_invalid(out,"docker_migration_copy_failed");goto restore;}
    if(nc_docker_migration_record(db,jobs,job,"verifying",journal,out)||nc_docker_migration_copy(db,jobs,job,journal,out,source,target,1)||fsync(target)){nc_docker_invalid(out,"docker_migration_verify_failed");goto restore;}
    struct json_object *mount=nc_docker_migration_mount(to);struct stat current;
    int same=mount&&json_object_equal(mount,nc_docker_member(journal,"mount"))&&!stat(to,&current)&&current.st_dev==dst.st_dev&&current.st_ino==dst.st_ino;
    if(mount){json_object_put(mount);}
    if(!same||stat(from,&current)||current.st_dev!=src.st_dev||current.st_ino!=src.st_ino){nc_docker_invalid(out,"docker_migration_target_changed");goto restore;}
    if(nc_docker_migration_publish_root(to,db,jobs,job,journal,out)){nc_docker_invalid(out,"docker_migration_switch_failed");goto restore;}
    if(nc_docker_migration_record(db,jobs,job,"starting",journal,out)||nc_docker_settings_service("start")||nc_docker_migration_readback(journal,to,out)){nc_docker_invalid(out,"docker_migration_readback_failed");goto restore;}
    struct json_object *desired=nc_docker_settings_fields(nc_docker_member(row,"config"));
    json_object_object_add(desired,"data_root",json_object_new_string(to));
    json_object_object_add(out,"ok",json_object_new_boolean(1));json_object_object_add(out,"phase",json_object_new_string("complete"));
    json_object_object_add(out,"applied",json_object_new_boolean(1));
    if(nc_docker_migration_commit(db,desired,out)){json_object_put(desired);nc_docker_invalid(out,"docker_migration_record_failed");goto restore;}
    json_object_put(desired);rc=0;goto done;
restore:
    if(!nc_docker_member(out,"error"))nc_docker_invalid(out,"docker_migration_stop_failed");
    json_object_object_add(out,"applied",json_object_new_boolean(0));
    nc_docker_migration_restore(db,jobs,job,journal,out);
done:
    if(source>=0){close(source);}if(target>=0){close(target);}if(db){sqlite3_close(db);}
    if(plan){json_object_put(plan);}if(row){json_object_put(row);}if(journal){json_object_put(journal);}
    if(settings_lock>=0){close(settings_lock);}g_nc_docker_migration_owner=0;if(lock>=0){close(lock);}return rc;
}

static int nc_docker_migration_submit(struct json_object *cfg,struct json_object *out)
{
    const char *const keys[]={"id","operation","confirm","revision","directory_ref","allow_stop",NULL};
    if(!nc_docker_keys(cfg,keys))return nc_docker_invalid(out,"invalid_docker_migration_fields");
    if(strcmp(nc_json_str_def(cfg,"operation",""),"storage_recover") &&
       (!nc_docker_string(nc_docker_member(cfg,"revision"),64)||!nc_json_bool_def(cfg,"allow_stop",0)))return nc_docker_invalid(out,"docker_migration_stop_confirmation_required");
    return nc_container_job_submit("docker_migration","docker-engine",json_object_to_json_string_ext(cfg,JSON_C_TO_STRING_PLAIN),out);
}
