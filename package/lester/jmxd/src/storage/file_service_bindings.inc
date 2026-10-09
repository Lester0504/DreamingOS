/* A published path is a pinned directory, never a second lookup of removable
 * media by pathname. Empty publication directories contain no user data. */
#include <blkid/blkid.h>
#include <sys/mount.h>
#include <sys/statfs.h>
#include <sys/sysmacros.h>
#ifndef JMX_SHARE_PUBLISH_ROOT
#define JMX_SHARE_PUBLISH_ROOT "/remote-share"
#endif

static void fs_mount_unescape(char *text)
{
    char *out=text;
    for(char *p=text;*p;p++){
        if(p[0]=='\\' && p[1]>='0' && p[1]<='7' && p[2]>='0' && p[2]<='7' && p[3]>='0' && p[3]<='7'){
            *out++=(p[1]-'0')*64+(p[2]-'0')*8+p[3]-'0';p+=3;
        }else *out++=*p;
    }
    *out='\0';
}

static struct json_object *fs_binding_identity(const char *path)
{
    char canonical[FS_MAX_PATH+1],line[8192],root[PATH_MAX],point[PATH_MAX],type[64],source[PATH_MAX];
    char best_root[PATH_MAX]="",best_point[PATH_MAX]="",best_type[64]="",best_source[PATH_MAX]="";
    struct stat st;struct statfs fs;
    if(!fs_share_path_ok(path,canonical,sizeof canonical) || strcmp(path,canonical) ||
       stat(path,&st)!=0 || statfs(path,&fs)!=0)return NULL;
    FILE *fp=fopen("/proc/self/mountinfo","re");if(!fp)return NULL;
    while(fgets(line,sizeof line,fp)){
        unsigned a,b;char *tail=strstr(line," - ");
        if(!tail || sscanf(line,"%*u %*u %u:%u %4095s %4095s",&a,&b,root,point)!=4 ||
           sscanf(tail+3,"%63s %4095s",type,source)!=2)continue;
        fs_mount_unescape(root);fs_mount_unescape(point);fs_mount_unescape(source);
        if(a!=major(st.st_dev) || b!=minor(st.st_dev) || (strcmp(point,"/") && !fs_path_prefix(path,point)) || strlen(point)<strlen(best_point))continue;
        snprintf(best_root,sizeof best_root,"%s",root);snprintf(best_point,sizeof best_point,"%s",point);
        snprintf(best_type,sizeof best_type,"%s",type);snprintf(best_source,sizeof best_source,"%s",source);
    }
    fclose(fp);if(!best_point[0])return NULL;
    char uuid[160]="",origin[PATH_MAX],boot[80]="",fsid[80];
    if(best_source[0]=='/'){
        blkid_probe probe=blkid_new_probe_from_filename(best_source);
        if(probe){const char *value;size_t len;
            blkid_probe_enable_partitions(probe,0);blkid_probe_set_superblocks_flags(probe,BLKID_SUBLKS_UUID);
            if(blkid_do_safeprobe(probe)==0 && blkid_probe_lookup_value(probe,"UUID",&value,&len)==0 && len<sizeof uuid)
                snprintf(uuid,sizeof uuid,"%s",value);
            blkid_free_probe(probe);
        }
    }
    const char *relative=path+(!strcmp(best_point,"/")?0:strlen(best_point));
    if(snprintf(origin,sizeof origin,"%s%s",!strcmp(best_root,"/")?"":best_root,relative)>=(int)sizeof origin)return NULL;
    if(!uuid[0]){
        fp=fopen("/proc/sys/kernel/random/boot_id","re");if(!fp)return NULL;
        char *got=fgets(boot,sizeof boot,fp);fclose(fp);if(!got)return NULL;boot[strcspn(boot,"\r\n")]='\0';
    }
    snprintf(fsid,sizeof fsid,"%08x:%08x",(unsigned)fs.f_fsid.__val[0],(unsigned)fs.f_fsid.__val[1]);
    struct json_object *o=json_object_new_object();
    json_object_object_add(o,"uuid",json_object_new_string(uuid));
    json_object_object_add(o,"origin",json_object_new_string(origin));
    json_object_object_add(o,"fstype",json_object_new_string(best_type));
    json_object_object_add(o,"inode",json_object_new_int64(st.st_ino));
    json_object_object_add(o,"device",json_object_new_int64(st.st_dev));
    json_object_object_add(o,"boot",json_object_new_string(boot));
    json_object_object_add(o,"fsid",json_object_new_string(fsid));
    return o;
}

static int fs_binding_equal(struct json_object *a,struct json_object *b)
{
    if(!a || !b || !fs_dav_int(a,"inode") || fs_dav_int(a,"inode")!=fs_dav_int(b,"inode") ||
       strcmp(fs_dav_str(a,"origin"),fs_dav_str(b,"origin")) ||
       strcmp(fs_dav_str(a,"fstype"),fs_dav_str(b,"fstype")))return 0;
    if(fs_dav_str(a,"uuid")[0])return !strcmp(fs_dav_str(a,"uuid"),fs_dav_str(b,"uuid"));
    return !strcmp(fs_dav_str(a,"boot"),fs_dav_str(b,"boot")) &&
        !strcmp(fs_dav_str(a,"fsid"),fs_dav_str(b,"fsid")) && fs_dav_int(a,"device")==fs_dav_int(b,"device");
}

static int fs_bindings_schema(sqlite3 *db)
{
    return fs_sql_exec(db,"CREATE TABLE IF NOT EXISTS file_share_binding("
        "service TEXT NOT NULL,id TEXT NOT NULL,path TEXT NOT NULL,identity_json TEXT NOT NULL,"
        "PRIMARY KEY(service,id));"
        "CREATE TABLE IF NOT EXISTS file_share_binding_error(service TEXT PRIMARY KEY,error TEXT NOT NULL);");
}

static struct json_object *fs_binding_load(sqlite3 *db,const char *service,const char *id,char *path)
{
    sqlite3_stmt *st=NULL;struct json_object *identity=NULL;
    if(fs_prepare(db,&st,"SELECT path,identity_json FROM file_share_binding WHERE service=?1 AND id=?2")!=0)return NULL;
    sqlite3_bind_text(st,1,service,-1,SQLITE_TRANSIENT);sqlite3_bind_text(st,2,id,-1,SQLITE_TRANSIENT);
    if(sqlite3_step(st)==SQLITE_ROW){
        if(path)snprintf(path,FS_MAX_PATH+1,"%s",fs_sql_text(st,0,""));
        identity=json_tokener_parse(fs_sql_text(st,1,"{}"));
    }
    sqlite3_finalize(st);return identity;
}

static int fs_binding_store(sqlite3 *db,const char *service,const char *id,const char *path,struct json_object *identity,int seed)
{
    sqlite3_stmt *st=NULL;
    const char *sql=seed?"INSERT OR IGNORE INTO file_share_binding VALUES(?1,?2,?3,?4)":
        "INSERT INTO file_share_binding VALUES(?1,?2,?3,?4) ON CONFLICT(service,id) DO UPDATE SET path=excluded.path,identity_json=excluded.identity_json";
    if(fs_prepare(db,&st,sql)!=0)return -1;
    sqlite3_bind_text(st,1,service,-1,SQLITE_TRANSIENT);sqlite3_bind_text(st,2,id,-1,SQLITE_TRANSIENT);
    sqlite3_bind_text(st,3,path,-1,SQLITE_TRANSIENT);
    sqlite3_bind_text(st,4,identity?json_object_to_json_string_ext(identity,JSON_C_TO_STRING_PLAIN):"{}",-1,SQLITE_TRANSIENT);
    int rc=fs_step_done(st);sqlite3_finalize(st);return rc;
}

static int fs_bindings_seed(sqlite3 *db)
{
    sqlite3_stmt *st=NULL;
    if(fs_prepare(db,&st,"SELECT 'samba',id,path FROM samba_share WHERE id NOT IN(SELECT id FROM file_share_binding WHERE service='samba') "
        "UNION ALL SELECT 'nfs',id,path FROM nfs_export WHERE id NOT IN(SELECT id FROM file_share_binding WHERE service='nfs')")!=0)return -1;
    int step,rc=0;
    while((step=sqlite3_step(st))==SQLITE_ROW){
        const char *path=fs_sql_text(st,2,"");struct json_object *identity=fs_binding_identity(path);
        if(fs_binding_store(db,fs_sql_text(st,0,""),fs_sql_text(st,1,""),path,identity,1)!=0)rc=-1;
        json_object_put(identity);
    }
    sqlite3_finalize(st);return step==SQLITE_DONE?rc:-1;
}

static int fs_binding_update(sqlite3 *db,const char *service,const char *id,const char *path,int enabled,struct json_object *payload)
{
    char previous[FS_MAX_PATH+1]="";struct json_object *old=fs_binding_load(db,service,id,previous),*now=NULL;
    int rebind=0,present=0,rc=-1;
    if(fs_json_bool(payload,"rebind",&rebind,&present)!=0)goto out;
    now=fs_binding_identity(path);
    if(!old || strcmp(previous,path) || rebind){
        if(!now)goto out;
        rc=fs_binding_store(db,service,id,path,now,0);
    }else rc=!enabled || fs_binding_equal(old,now)?0:-1;
out:json_object_put(old);json_object_put(now);return rc;
}

static int fs_binding_available(sqlite3 *db,const char *service,const char *id,const char *path)
{
    char previous[FS_MAX_PATH+1]="";struct json_object *old=fs_binding_load(db,service,id,previous),*now=fs_binding_identity(path);
    int ok=!strcmp(previous,path) && fs_binding_equal(old,now);json_object_put(old);json_object_put(now);return ok;
}

static int fs_binding_target(const char *id,char *path,size_t size)
{
    return fs_id_ok(id) && snprintf(path,size,JMX_SHARE_PUBLISH_ROOT "/%s",id)<(int)size;
}

static int fs_binding_mounted(const char *path)
{
    char line[8192],point[PATH_MAX];int found=0;
    FILE *fp=fopen("/proc/self/mountinfo","re");if(!fp)return 0;
    while(fgets(line,sizeof line,fp))if(sscanf(line,"%*u %*u %*s %*s %4095s",point)==1){
        fs_mount_unescape(point);if(!strcmp(point,path)){found=1;break;}
    }
    fclose(fp);return found;
}

static int fs_binding_published(const char *id,const char *path)
{
    char target[FS_MAX_PATH+1];struct stat a,b;
    return fs_binding_target(id,target,sizeof target) && fs_binding_mounted(target) &&
        stat(path,&a)==0 && stat(target,&b)==0 && a.st_dev==b.st_dev && a.st_ino==b.st_ino;
}

static int fs_binding_pin(const char *id,const char *path,struct json_object *identity,char *target,size_t size)
{
    struct stat source,current,base;
    if(!fs_binding_target(id,target,size))return -1;
    struct json_object *now=fs_binding_identity(path);
    int available=fs_binding_equal(identity,now);json_object_put(now);
    if(!available)return 0;
#ifdef JMX_SHARE_BINDING_TEST_NO_MOUNT
    /* Transaction tests run unprivileged. Real mount/client tests use the
     * production branch inside a disposable VM. */
    snprintf(target,size,"%s",path);return 1;
#else
    if(fs_binding_published(id,path))return 1;
    if(mkdir(JMX_SHARE_PUBLISH_ROOT,0755)!=0 && errno!=EEXIST)return -1;
    if(lstat(JMX_SHARE_PUBLISH_ROOT,&base)!=0 || !S_ISDIR(base.st_mode) || base.st_uid!=0 || (base.st_mode&0022))return -1;
    if(fs_binding_mounted(target) && umount2(target,MNT_DETACH)!=0)return -1;
    if(mkdir(target,0000)!=0 && errno!=EEXIST)return -1;
    if(lstat(target,&base)!=0 || !S_ISDIR(base.st_mode) || base.st_uid!=0 || (base.st_mode&0777))return -1;
    int fd=open(path,O_PATH|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW);if(fd<0)return -1;
    now=fs_binding_identity(path);
    int ok=fstat(fd,&source)==0 && fs_binding_equal(identity,now) &&
        stat(path,&current)==0 && source.st_dev==current.st_dev && source.st_ino==current.st_ino;
    json_object_put(now);
    char descriptor[64];snprintf(descriptor,sizeof descriptor,"/proc/self/fd/%d",fd);
    if(ok)ok=mount(descriptor,target,NULL,MS_BIND,NULL)==0;
    close(fd);return ok?1:-1;
#endif
}

static int fs_binding_prepare(sqlite3 *db,const char *service,const char *id,const char *path,char *target,size_t size)
{
    char previous[FS_MAX_PATH+1]="";
    struct json_object *identity=fs_binding_load(db,service,id,previous);
    int rc=!strcmp(previous,path)?fs_binding_pin(id,path,identity,target,size):0;
    json_object_put(identity);return rc;
}

static void fs_binding_unpin(const char *id)
{
    char target[FS_MAX_PATH+1];if(!fs_binding_target(id,target,sizeof target))return;
    if(fs_binding_mounted(target))umount2(target,MNT_DETACH);
    rmdir(target);
}

static void fs_binding_sweep(sqlite3 *db,const char *service)
{
#ifndef JMX_SHARE_BINDING_TEST_NO_MOUNT
    DIR *dir=opendir(JMX_SHARE_PUBLISH_ROOT);if(!dir)return;
    struct dirent *entry;
    while((entry=readdir(dir))){
        char target[FS_MAX_PATH+1];size_t prefix=strlen(service);
        if(strncmp(entry->d_name,service,prefix) || entry->d_name[prefix]!='-' || !fs_binding_target(entry->d_name,target,sizeof target))continue;
        sqlite3_stmt *st=NULL;int keep=0;
        const char *sql=!strcmp(service,"samba")?"SELECT path FROM samba_share WHERE id=?1 AND enabled=1":"SELECT path FROM nfs_export WHERE id=?1 AND enabled=1";
        if(fs_prepare(db,&st,sql)!=0)continue;
        sqlite3_bind_text(st,1,entry->d_name,-1,SQLITE_TRANSIENT);
        if(sqlite3_step(st)==SQLITE_ROW)keep=fs_binding_available(db,service,entry->d_name,fs_sql_text(st,0,""));
        sqlite3_finalize(st);
        if(!keep)fs_binding_unpin(entry->d_name);
    }
    closedir(dir);
#endif
}

static void fs_binding_status(sqlite3 *db,struct json_object *item,const char *service,const char *id,const char *path)
{
    char target[FS_MAX_PATH+1];int ok=fs_binding_available(db,service,id,path);
    json_object_object_add(item,"path_available",json_object_new_boolean(ok));
    json_object_object_add(item,"path_reason",json_object_new_string(ok?"":"directory_binding_changed"));
    int has_target=fs_binding_target(id,target,sizeof target);
    json_object_object_add(item,"published",json_object_new_boolean(has_target && fs_binding_mounted(target)));
    if(has_target)json_object_object_add(item,"publish_path",json_object_new_string(target));
    json_object_object_add(item,"binding_recovery",json_object_new_string("original_identity_only"));
}

/* Runs as its own procd instance so disk removal does not wait for an HTTP
 * read and slow protocol reloads do not block the core's event loop. */
int jmx_file_service_bindings_watch(void)
{
    for(;;){
        sqlite3 *db=NULL;
        if(fs_db_open(&db)==0 && fs_sql_exec(db,"BEGIN IMMEDIATE")==0){
            const char *services[]={"samba","nfs"};
            for(size_t i=0;i<2;i++){
                const char *service=services[i],*config=i?JMX_NFS_CONFIG_PATH:JMX_SAMBA_CONFIG_PATH;
                if(access(fs_control_script(service),X_OK)!=0)continue;
                struct fs_buffer rendered={0};struct fs_snapshot old={0};
                fs_binding_sweep(db,service);
                int rc=i?fs_render_nfs(db,&rendered):fs_render_samba(db,&rendered);
                int changed=rc==0 && fs_snapshot_read(config,&old)==0 &&
                    (!old.existed || old.len!=rendered.len || memcmp(old.data,rendered.data,rendered.len));
                sqlite3_stmt *st=NULL;int retry=0;
                if(fs_prepare(db,&st,"SELECT error FROM file_share_binding_error WHERE service=?1")==0){
                    sqlite3_bind_text(st,1,service,-1,SQLITE_STATIC);retry=sqlite3_step(st)==SQLITE_ROW && fs_sql_text(st,0,"")[0];
                }
                if(st)sqlite3_finalize(st);st=NULL;
                const char *reason="";
                if(changed || retry){
                    if(fs_control_running(service)){
                        struct fs_snapshot prior={0};struct fs_exec_result result={0};const char *action="";int replaced=0;
                        rc=fs_apply_new_config(db,service,&prior,&result,&action,&reason,&replaced);fs_snapshot_free(&prior);
                    }else if(rc==0)rc=fs_atomic_replace(config,rendered.data,rendered.len,0600);
                }
                if(fs_prepare(db,&st,"INSERT INTO file_share_binding_error VALUES(?1,?2) ON CONFLICT(service) DO UPDATE SET error=excluded.error")==0){
                    sqlite3_bind_text(st,1,service,-1,SQLITE_STATIC);sqlite3_bind_text(st,2,rc==0?"":reason[0]?reason:"binding_projection_failed",-1,SQLITE_TRANSIENT);sqlite3_step(st);
                }
                if(st)sqlite3_finalize(st);fs_snapshot_free(&old);fs_buffer_free(&rendered);
            }
            fs_dav_reconcile(db);
            fs_ftp_reconcile(db);
            fs_sql_exec(db,"COMMIT");
        }
        if(db)sqlite3_close(db);
        sleep(2);
    }
}
